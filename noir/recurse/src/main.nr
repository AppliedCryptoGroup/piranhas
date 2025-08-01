use dep::std::verify_proof;

mod attest;

fn main(
    verification_key: [Field; 128],
    proof: [Field; 456],
    public_inputs: [Field; 3],
    key_hash: Field,
    w_path_elements: [Field; 10], // Merkle path
    w_path_indices: [Field; 10], // Merkle path
    k: Field,  // PRF key
    rsp: Field, 
    chall: Field,
    t: pub Field,
    pk_x: pub Field,  // manufacturer 
    pk_y: pub Field,  // manufacturer 
    sig: [u8; 64] // by manufacturer 
) {
    verify_proof(verification_key, proof, public_inputs, key_hash);
    attest::attest(
        w_path_elements, 
        w_path_indices,
        k,
        rsp,
        chall,
        t,
        pk_x,
        pk_y,
        sig
    );
}
