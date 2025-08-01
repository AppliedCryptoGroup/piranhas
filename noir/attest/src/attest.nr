use dep::schnorr::{verify_signature, assert_valid_signature};
use dep::std::embedded_curve_ops::{EmbeddedCurvePoint,EmbeddedCurveScalar,embedded_curve_add,fixed_base_scalar_mul};
use std::hash::pedersen_hash;

// Computes MiMC([left, right])
fn hash_left_right(left: Field, right: Field) -> Field {
    let hasher: Field = pedersen_hash([left, right]);
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

#[export]
pub fn commit_to_tag(
    tag: Field,
) -> EmbeddedCurvePoint {
    let ec_tag = EmbeddedCurveScalar::from_field(tag);
    let g_tag = fixed_base_scalar_mul(ec_tag);
    g_tag
}

#[export]
pub fn append_tags(
    tag: Field,
    at: EmbeddedCurvePoint
) -> EmbeddedCurvePoint {
    let ec_tag = EmbeddedCurveScalar::from_field(tag);
    let g_tag = fixed_base_scalar_mul(ec_tag);
    let result = embedded_curve_add(g_tag, at);
    result
}


#[export]
pub fn attest(
    w_path_elements: [Field; 10], // Merkle path
    w_path_indices: [Field; 10], // Merkle path
    k: Field,  // PRF key
    rsp: Field, 
    chall: Field,
    t: Field,
    pk_x: Field,  // manufacturer 
    pk_y: Field,  // manufacturer 
    signature: [u8; 64]  // by manufacturer 
) {

    let calculated_t = pedersen_hash([chall, k]);
    // std::println(calculated_t);
    assert_eq(calculated_t, t);

    let commitment = pedersen_hash([chall, rsp]);
    let root = merkle_tree_checker(commitment, w_path_elements, w_path_indices);
    let auth_root = pedersen_hash([root, k]);
    // std::println(auth_root);
    let root_array: [u8; 32] = auth_root.to_le_bytes();
    // std::println(root_array);

    let pub_key = EmbeddedCurvePoint { x: pk_x, y: pk_y, is_infinite: false };
    let valid_signature = verify_signature(pub_key, signature, root_array);
    assert(valid_signature);
    assert_valid_signature(pub_key, signature, root_array);

    // let a = commitment;
    // let b = root;
    // let ab = a+b;

    // let at1 = commit_to_tag(a);
    // let at2 = append_tags(b, at1);

    // let expected_at2 = commit_to_tag(ab);

    // assert_eq(at2, expected_at2);

}