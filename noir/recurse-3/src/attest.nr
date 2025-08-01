// fn main(a: u32, b: pub u32, c: pub u32) {
//     assert(a != b);
//     assert(a * b == c);
// }

use dep::std::hash::poseidon;
use dep::schnorr::{verify_signature, assert_valid_signature};
use dep::std::embedded_curve_ops::{EmbeddedCurvePoint};

#[export]
pub fn attest(
    x: Field, 
    y: Field,
    expected_hash: Field,
    pub_key_x: Field,
    pub_key_y: Field,
    signature: [u8; 64],
    message: [u8; 10]
) {
    let hashh = poseidon::bn254::hash_2([x, y]);
    assert_eq(hashh, expected_hash);

    let pub_key = EmbeddedCurvePoint { x: pub_key_x, y: pub_key_y, is_infinite: false };
    let valid_signature = verify_signature(pub_key, signature, message);
    assert(valid_signature);
    assert_valid_signature(pub_key, signature, message);
}

