// fn main(a: u32, b: pub u32, c: pub u32) {
//     assert(a != b);
//     assert(a * b == c);
// }

use dep::std::hash::poseidon;
use dep::schnorr::{verify_signature, assert_valid_signature};
use dep::std::embedded_curve_ops::{EmbeddedCurvePoint};
use std::hash::pedersen_hash;

// Computes MiMC([left, right])
fn hash_left_right(left: Field, right: Field) -> Field {
    let hasher: Field = poseidon::bn254::hash_2([left, right]);
    hasher
}

// if s == 0 returns [in[0], in[1]]
// if s == 1 returns [in[1], in[0]]
fn dual_mux(input: [Field; 2], s: Field) -> [Field; 2] {
    assert(s * (1 - s) == 0);
    let out0 = (input[1] - input[0]) * s + input[0];
    let out1 = (input[0] - input[1]) * s + input[1];
    [out0, out1]
}

// Verifies that merkle proof is correct for given merkle root and a leaf
// path_indices input is an array of 0/1 selectors telling whether given path_element is on the left or right side of merkle path
pub fn merkle_tree_checker(leaf: Field, path_elements: [Field], path_indices: [Field]) -> Field {
    let levels = path_elements.len();
    let mut current_hash = leaf;

    for i in 0..levels {
        let muxed = dual_mux([current_hash, path_elements[i]], path_indices[i]);
        current_hash = hash_left_right(muxed[0], muxed[1]);
    }

    current_hash
}

// #[export]
// pub fn attest(
//     x: Field, 
//     y: Field,
//     expected_hash: Field,
//     pub_key_x: Field,
//     pub_key_y: Field,
//     signature: [u8; 64],
//     message: [u8; 10]
// ) {
//     let hashh = poseidon::bn254::hash_2([x, y]);
//     assert_eq(hashh, expected_hash);

//     let pub_key = EmbeddedCurvePoint { x: pub_key_x, y: pub_key_y, is_infinite: false };
//     let valid_signature = verify_signature(pub_key, signature, message);
//     assert(valid_signature);
//     assert_valid_signature(pub_key, signature, message);
// }

#[export]
pub fn attest(
    v: Field,  // Merkle root 
    w_path_elements: [Field; 10], // Merkle path
    w_path_indices: [Field; 10], // Merkle path
    k: Field,  // PRF key
    rsp: Field, 
    chall: Field,
    t: Field,
    pk_x: Field,  // manufacturer 
    pk_y: Field,  // manufacturer 
    signature: [u8; 64],  // by manufacturer 
    message: [u8; 10]
) {

  let calculated_t = pedersen_hash([chall, k]);
  std::println(calculated_t);
  assert_eq(calculated_t, t);

  let commitment = pedersen_hash([chall, rsp]);
  let root = merkle_tree_checker(commitment, w_path_elements, w_path_indices);
  std::println(root);

  assert_eq(root, v);

  let pub_key = EmbeddedCurvePoint { x: pk_x, y: pk_y, is_infinite: false };
  let valid_signature = verify_signature(pub_key, signature, message);
  assert(valid_signature);
  assert_valid_signature(pub_key, signature, message);

}