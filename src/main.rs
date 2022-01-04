mod network;
mod blockchain;
use std::env;
use sha2::{Sha256, Digest};
//use crate::network;

fn main() {
    /*
    let args: Vec<String> = env::args().collect();
    println!("{:?}", args);
    match &args[1][..] {
        "client" => network::client(),
        "server" => network::server(),
        _ => (),
    }
    let (private_key, public_key) = blockchain::generate_key_pair();
    let (private_key2, public_key2) = blockchain::generate_key_pair();
    let foo = blockchain::Transaction::new(public_key, private_key, public_key2, 10.0, 1);
    */

    let mut hasher = Sha256::new();
    hasher.update("hello");
    let hash = blockchain::SHA256Hash::from(hasher.finalize());
    println!("{:?}", hash);
}
