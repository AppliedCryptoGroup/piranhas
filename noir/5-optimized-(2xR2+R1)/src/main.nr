use dep::std::verify_proof;
use dep::std::embedded_curve_ops::{EmbeddedCurvePoint,embedded_curve_add};

mod attest;

fn main(
    verification_key: [Field; 128],
    proof: [Field; 456],
    public_inputs: [Field; 3],
    key_hash: Field,
    prev_at_x: pub Field,  
    prev_at_y: pub Field,  
    verification_key2: [Field; 128],
    proof2: [Field; 456],
    public_inputs2: [Field; 3],
    key_hash2: Field,
    prev_at2_x: pub Field,  
    prev_at2_y: pub Field,  
    verification_key3: [Field; 128],
    proof3: [Field; 456],
    public_inputs3: [Field; 3],
    key_hash3: Field,
    prev_at3_x: pub Field,  
    prev_at3_y: pub Field,  
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
    verify_proof(verification_key2, proof2, public_inputs2, key_hash2);
    verify_proof(verification_key3, proof3, public_inputs3, key_hash3);

    let prev_at = EmbeddedCurvePoint { x: prev_at_x, y: prev_at_y, is_infinite: false };
    let prev_at2 = EmbeddedCurvePoint { x: prev_at2_x, y: prev_at2_y, is_infinite: false };
    let prev_at3 = EmbeddedCurvePoint { x: prev_at3_x, y: prev_at3_y, is_infinite: false };
    let at = EmbeddedCurvePoint { x: at_x, y: at_y, is_infinite: false };
    let result = embedded_curve_add(prev_at, prev_at2);
    let result2 = embedded_curve_add(result, prev_at3);
    
    // std::println(result);
    // std::println(prev_at2);

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

    let final_result = attest::append_tags(t, result2);

    // std::println(final_result);

    assert_eq(final_result, at);

}
