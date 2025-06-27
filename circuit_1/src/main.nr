// fn main(a: u32, b: pub u32, c: pub u32) {
//     assert(a != b);
//     assert(a * b == c);
// }

use dep::std::println;
use dep::std::hash::poseidon;

fn main(x: Field, y: pub Field, expected_hash: pub Field) {
    let hashh = poseidon::bn254::hash_2([x, y]);
    println(x);
    println(y);
    println(hashh);
    assert(x != y);
    assert_eq(hashh, expected_hash);
}