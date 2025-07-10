use dep::std::verify_proof;
use dep::std::hash;
use dep::std::hash::poseidon;

fn main(
    verification_key: [Field; 128],
    proof: [Field; 456],
    public_inputs: [Field; 2],
    key_hash: Field,
    proof2: [Field; 456],
    public_inputs2: [Field; 2],
    proof3: [Field; 456],
    public_inputs3: [Field; 2],
    x: Field, y: pub Field, expected_hash: pub Field
) {
    verify_proof(verification_key, proof, public_inputs, key_hash);
    verify_proof(verification_key, proof2, public_inputs2, key_hash);
    verify_proof(verification_key, proof3, public_inputs3, key_hash);
    let hashh = poseidon::bn254::hash_2([x, y]);
    assert_eq(hashh, expected_hash);
}
