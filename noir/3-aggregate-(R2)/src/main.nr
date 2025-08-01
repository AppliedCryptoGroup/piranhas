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
    at_x: pub Field,  
    at_y: pub Field
) {
    verify_proof(verification_key, proof, public_inputs, key_hash);
    verify_proof(verification_key2, proof2, public_inputs2, key_hash2);
    

    let prev_at = EmbeddedCurvePoint { x: prev_at_x, y: prev_at_y, is_infinite: false };
    let prev_at2 = EmbeddedCurvePoint { x: prev_at2_x, y: prev_at2_y, is_infinite: false };
    let at = EmbeddedCurvePoint { x: at_x, y: at_y, is_infinite: false };
    let result = embedded_curve_add(prev_at, prev_at2);
    
    // std::println(result);
    // std::println(prev_at2);

    assert_eq(result, at);

}
