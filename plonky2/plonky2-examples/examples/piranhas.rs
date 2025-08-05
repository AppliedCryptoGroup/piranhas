use log::{info, Level};
use plonky2::{plonk::{config::{Hasher, PoseidonGoldilocksConfig, GenericConfig, GenericHashOut}, circuit_data::{CircuitConfig, CircuitData}, circuit_builder::CircuitBuilder, prover::prove}, iop::{witness::PartialWitness, target::Target}, util::timing::{self, TimingTree}, hash::{hash_types::HashOut, hashing::{hash_n_to_hash_no_pad, hash_n_to_m_no_pad}, poseidon::PoseidonPermutation}};
use plonky2_ecdsa::gadgets::{nonnative::CircuitBuilderNonNative, biguint::WitnessBigUint};
use plonky2_ecgfp5::{curve::{curve::{Point, WeierstrassPoint}, scalar_field::Scalar}, gadgets::{base_field::{CircuitBuilderGFp5, PartialWitnessQuinticExt, QuinticExtensionTarget}, curve::{CircuitBuilderEcGFp5, PartialWitnessCurve}, scalar_field::CircuitBuilderScalar}};
use plonky2_field::{extension::quintic::QuinticExtension, goldilocks_field::GoldilocksField, types::{Field, PrimeField, Sample}};
use rand::{thread_rng, Rng};

use anyhow::Result;
use log::{LevelFilter};
use env_logger::Builder;
use plonky2::iop::witness::{WitnessWrite};
use plonky2::hash::poseidon::{PoseidonHash};
use plonky2::hash::hash_types::RichField;
use plonky2_field::extension::Extendable;

pub const SPONGE_WIDTH: usize = 12;
pub const SPONGE_RATE: usize = 8;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher};

// Recursion imports 
use plonky2::gates::noop::NoopGate;
use plonky2::plonk::proof::{ProofWithPublicInputs};

// Sig imports

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);


// Circuit setup - leave as is
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

// we define a hash function whose digest is 5 GFp5 elems
// note: this doesn't apply any padding, so this is vulnerable to length extension attacks
fn sig_hash(message: &[F]) -> [F; 5] {
	let mut res = [F::ZERO; 5];
	let out = hash_n_to_m_no_pad::<F, PoseidonPermutation<F>>(message, 5);
	res.copy_from_slice(&out[..5]);

	res
}

fn sig_hash_circuit(builder: &mut CircuitBuilder<F, D>, message: &[Target]) -> [Target; 5] {
	let mut state = [(); SPONGE_WIDTH].map(|_| builder.zero());

    // Absorb all input chunks.
    for input_chunk in message.chunks(SPONGE_RATE) {
        state[..input_chunk.len()].copy_from_slice(input_chunk);
		// state = builder.permute::<<PoseidonGoldilocksConfig as GenericConfig<D>>::Hasher>(state);
    }
    // Squeeze until we have the desired number of outputs.
	[
		state[0],
		state[1],
		state[2],
		state[3],
		state[4],
	]
}

fn sign(
    rsp: F,
    path: [F;5],
    k_prf: F,
    chall: F,
    sk: Scalar,
) -> Result<(Scalar,Scalar)>{
    let com = sig_hash(&[rsp, chall]);

    let mut hsh = com;
    for i in 0..5 {
        let mut x = hsh.to_vec();
        x.push(path[i]);
        hsh = sig_hash(&x);
    }
    let root = hsh;
    let mut m = root.to_vec();
    m.push(k_prf);
	
    let mut rng = thread_rng();
	let k  = Scalar::sample(&mut rng);

	// Compute R = k*G
	let r = Point::GENERATOR * k;

	// 4. e = H(R || m)
	let mut preimage = r.encode().0.to_vec();
	preimage.extend(m);
	let e_elems = sig_hash(&preimage);
	let e = Scalar::from_gfp5(QuinticExtension(e_elems));

	// 5. s = k - e*sk
	// signature = (s, e)
	let s = k - e * sk;

    Ok((s,e))
}

fn single_client_proof(
    config: &CircuitConfig,
    rsp: F,
    path: [F;5],
    k_prf: F,
    chall: F,
    pk: Point,
    sig: (Scalar,Scalar),
) -> Result<(ProofTuple<F,C,D>)>
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    // Circuit implementation
    let rsp_tgt = builder.add_virtual_target();
    let chall_tgt = builder.add_virtual_target();
    builder.register_public_input(chall_tgt);

    let com = builder.hash_n_to_hash_no_pad::<PoseidonHash>([rsp_tgt,chall_tgt].to_vec());

    let mut hsh = com;
    let path_tgt: Vec<Target> = path.iter().map(|_| builder.add_virtual_target()).collect(); 
    for i in 0..5 {
        let mut x = hsh.elements.to_vec();
        x.push(path_tgt[i]);
        hsh = builder.hash_n_to_hash_no_pad::<PoseidonHash>(x);
    }
    let root = hsh;
    builder.register_public_inputs(&root.elements);

    let kprf_tgt = builder.add_virtual_target();
    let tag = sig_hash_circuit(&mut builder,&[kprf_tgt,chall_tgt].to_vec());
    let tag_scalar = builder.encode_quintic_ext_as_scalar(QuinticExtensionTarget(tag));
	let g_tgt = builder.curve_constant(Point::GENERATOR.to_weierstrass());
    let tag_point = builder.curve_scalar_mul(g_tgt, &tag_scalar);
    builder.register_curve_public_input(tag_point);


    let mut m = root.elements.to_vec();
    m.push(kprf_tgt);

    // vfy sig 
    let (s,e) = sig;
	let s_tgt = builder.constant_nonnative::<Scalar>(s);
	let e_tgt = builder.constant_nonnative::<Scalar>(e);

	let g_tgt = builder.curve_constant(Point::GENERATOR.to_weierstrass());
	let pk_tgt = builder.curve_constant(pk.to_weierstrass());

	// r_v = s*G + e*pk
	let r_v = builder.curve_muladd_2(
		g_tgt,
		pk_tgt,
		&s_tgt,
		&e_tgt
	);

	let mut preimage = builder.curve_encode_to_quintic_ext(r_v).0.to_vec();
	preimage.extend(&m);
	let e_v_ext = QuinticExtensionTarget(
		sig_hash_circuit(&mut builder, &preimage)
	);
	let e_v = builder.encode_quintic_ext_as_scalar(e_v_ext);
    // TODO debug and verify
    

    let mut pw = PartialWitness::new();
    pw.set_target(rsp_tgt,rsp)?;
    pw.set_target(chall_tgt, chall)?;
    pw.set_target(kprf_tgt, k_prf)?;
    for i in 0..5 {
        pw.set_target(path_tgt[i], path[i])?;
    }

    let mut timing = TimingTree::new("build witness", Level::Info);
    let data = builder.build::<C>();
    timing.print();

    timing = TimingTree::new("prove", Level::Info);
    let proof = prove::<F, C, D>(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();
    
    println!("Successfully generated proof with tag: {:?} and root: {:?}", 1 , &proof.public_inputs);

    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}

fn recursive_proof(
    inner: &ProofTuple<F, C, D>,
    inner2: &ProofTuple<F, C, D>,
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> Result<ProofTuple<F, C, D>>
where
    <PoseidonGoldilocksConfig as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    let (inner_proof, inner_vd, inner_cd) = inner;
    let pt = builder.add_virtual_proof_with_pis(inner_cd);

    let inner_data = builder.add_virtual_verifier_data(inner_cd.config.fri_config.cap_height);

    builder.verify_proof::<C>(&pt, &inner_data, inner_cd);

    let (inner_proof2, inner_vd2, inner_cd2) = inner2;
    let pt2 = builder.add_virtual_proof_with_pis(inner_cd2);

    let inner_data2 = builder.add_virtual_verifier_data(inner_cd.config.fri_config.cap_height);

    builder.verify_proof::<C>(&pt2, &inner_data2, inner_cd2);

    //let mut tmp = inner_proof.public_inputs[5..10].try_into()?;
    //let ext = QuinticExtension(tmp);
    //println!("{:?}",tmp);
    // let agg_tag = builder.curve_constant(WeierstrassPoint::decode(ext).expect("decoding should succeed"));    
    // let add_tag = builder.curve_constant(WeierstrassPoint::decode(QuinticExtension(inner_proof2.public_inputs[5..10].try_into()?)).expect("decoding should succeed"));

    // let new_agg_tag = builder.curve_add(agg_tag, add_tag);
    // builder.register_curve_public_input(new_agg_tag);

    if let Some(min_degree_bits) = min_degree_bits {
        // We don't want to pad all the way up to 2^min_degree_bits, as the builder will
        // add a few special gates afterward. So just pad to 2^(min_degree_bits
        // - 1) + 1. Then the builder will pad to the next power of two,
        // 2^min_degree_bits.
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let data = builder.build::<C>();

    let mut pw = PartialWitness::new();
    let mut timing = TimingTree::new("build witness rec", Level::Info);
    pw.set_proof_with_pis_target(&pt, inner_proof)?;
    pw.set_verifier_data_target(&inner_data, inner_vd)?;
    pw.set_proof_with_pis_target(&pt2, inner_proof2)?;
    pw.set_verifier_data_target(&inner_data2, inner_vd2)?;
    timing.print();

    timing = TimingTree::new("prove rec", Level::Info);
    let proof = prove::<F, C, D>(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    println!("Successfully generated a recursive proof");

    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}


fn main() -> Result<()> {
    // enable logging
    Builder::new()
        .filter_level(LevelFilter::Info)
        .init();
    info!("Starting program");

    // Sample initial witness
    let mut rng = thread_rng();
    let rsp = F::sample(&mut rng);
    // in practice, test first which witness we need. For benchmarking irrelevant
    let path = std::array::from_fn(|_| F::sample(&mut rng));
    let k_prf = F::sample(&mut rng);
    let chall = F::sample(&mut rng);

    // generate signature
	let sk  = Scalar::sample(&mut rng);
    let pk = Point::GENERATOR * sk;
    let sig= sign(rsp,path,k_prf,chall,sk)?;

    // do a single proof
    let config_zk = CircuitConfig::standard_recursion_zk_config();
    let inner = single_client_proof(&config_zk,rsp,path,k_prf,chall,pk,sig).unwrap();

    // do another proof
    let k_prf2 = F::sample(&mut rng);
    let inner2 = single_client_proof(&config_zk,rsp,path,k_prf2,chall,pk,sig).unwrap();

    // do a recursive proof
    let config = CircuitConfig::standard_recursion_config();
    let _outer = recursive_proof(&inner, &inner2, &config, None)?;

    Ok(())
}
