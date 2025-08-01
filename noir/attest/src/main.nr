// fn main(a: u32, b: pub u32, c: pub u32) {
//     assert(a != b);
//     assert(a * b == c);
// }

mod attest;

fn main( 
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

