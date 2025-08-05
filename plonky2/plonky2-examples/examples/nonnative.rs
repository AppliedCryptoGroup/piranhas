use anyhow::Result;
use log::{info,Level,LevelFilter};
use env_logger::Builder;
use plonky2::{
    field::{secp256k1_scalar::Secp256K1Scalar, secp256k1_base::Secp256K1Base, types::Sample},
    iop::witness::PartialWitness,
    plonk::{
        prover::prove,
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
    util::timing::{TimingTree},
};
use plonky2_ecdsa::{
    curve::{
        curve_types::{Curve, CurveScalar},
        secp256k1::Secp256K1,
    },
    gadgets::{
        curve::CircuitBuilderCurve, nonnative::CircuitBuilderNonNative
    },
};

fn main() -> Result<()> {
    Builder::new()
        .filter_level(LevelFilter::Info)
        .init();
    info!("Starting program");

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Curve = Secp256K1;

    let config = CircuitConfig::standard_ecc_config();
    let pw = PartialWitness::new();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let sk = Secp256K1Scalar::rand();
    let pk = (CurveScalar(sk) * Curve::GENERATOR_PROJECTIVE).to_affine();

    let sk2 = Secp256K1Scalar::rand();
    let pk2 = (CurveScalar(sk2) * Curve::GENERATOR_PROJECTIVE).to_affine();
    
    let tgt = builder.constant_nonnative(sk);
    let tgt2 = builder.constant_affine_point(pk);
    let tgt3 = builder.constant_nonnative(sk2);
    let tgt4 = builder.constant_affine_point(pk2);

    
    let mut res = builder.curve_add(&tgt2, &tgt4);

    
    for _i in 1..2 {
        res = builder.curve_add(&tgt4, &res);
        res = builder.curve_scalar_mul(&res, &tgt);
    }
    

    let mut timing = TimingTree::new("build witness", Level::Info);
    let data = builder.build::<C>();
    timing.print();

    timing = TimingTree::new("prove", Level::Info);
    let proof = prove::<F, C, D>(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    data.verify(proof)?;
    Ok(())

}

