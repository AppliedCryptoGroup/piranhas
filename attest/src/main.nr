// fn main(a: u32, b: pub u32, c: pub u32) {
//     assert(a != b);
//     assert(a * b == c);
// }

mod attest;

fn main( 
    v: Field,  // Merkle root 
    w_path_elements: [Field; 10], // Merkle path
    w_path_indices: [Field; 10], // Merkle path
    k: Field,  // PRF key
    rsp: Field, 
    chall: Field,
    t: Field,
    pk_x: Field,  // manufacturer 
    pk_y: Field,  // manufacturer 
    sig: [u8; 64],  // by manufacturer 
    message: [u8; 10]
) {
    attest::attest(
        v,
        w_path_elements, 
        w_path_indices,
        k,
        rsp,
        chall,
        t,
        pk_x,
        pk_y,
        sig,
        message
    );
}

