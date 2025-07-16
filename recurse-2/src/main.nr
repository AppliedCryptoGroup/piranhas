use dep::std::verify_proof;
use dep::std::hash;
use dep::std::hash::poseidon;

mod attest;

fn main(
    verification_key: [Field; 128],
    proof: [Field; 456],
    public_inputs: [Field; 2],
    key_hash: Field,
    proof2: [Field; 456],
    public_inputs2: [Field; 2],
    x: Field, 
    y: pub Field, 
    expected_hash: pub Field,
    pub_key_x: Field,
    pub_key_y: Field,
    signature: [u8; 64],
    message: [u8; 10]
) {
    verify_proof(verification_key, proof, public_inputs, key_hash);
    verify_proof(verification_key, proof2, public_inputs2, key_hash);

    attest::attest(x, y, expected_hash, pub_key_x, pub_key_y, signature, message);
}
