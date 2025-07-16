// fn main(a: u32, b: pub u32, c: pub u32) {
//     assert(a != b);
//     assert(a * b == c);
// }

mod attest;

fn main(
    x: Field, 
    y: pub Field,
    expected_hash: pub Field,
    pub_key_x: Field,
    pub_key_y: Field,
    signature: [u8; 64],
    message: [u8; 10]
) {
    attest::attest(x, y, expected_hash, pub_key_x, pub_key_y, signature, message);
}

