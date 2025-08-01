use dep::std::verify_proof;
use dep::std::embedded_curve_ops::{EmbeddedCurvePoint};

mod attest;

fn main(
    verification_key: [Field; 128],
    proof: [Field; 456],
    public_inputs: [Field; 3],
    key_hash: Field,
    prev_at_x: pub Field,  
    prev_at_y: pub Field,  
    w_path_elements: [Field; 10], // Merkle path
    w_path_indices: [Field; 10], // Merkle path
    k: Field,  // PRF key
    rsp: Field, 
    chall: Field,
    t: pub Field,
    at_x: pub Field,  
    at_y: pub Field,  
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

    let prev_at = EmbeddedCurvePoint { x: prev_at_x, y: prev_at_y, is_infinite: false };
    let at = EmbeddedCurvePoint { x: at_x, y: at_y, is_infinite: false };
    let at2 = attest::append_tags(t, prev_at);

    // let pub_tag = attest::commit_to_tag(t);
    // std::println(pub_tag);
    // std::println(at2);

    assert_eq(at2, at);

}
