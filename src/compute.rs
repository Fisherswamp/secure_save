use sha2::{Sha256, Digest};
use hex;


pub fn hash_and_salt(password: &String) {
    let mut hash = calculate_hash(password);
    for _ in 0..7 {
        hash = calculate_hash(&hash);
    }
    println!("Hash is: {}", hash);
}

fn calculate_hash(object_to_hash: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.input(object_to_hash);
    let hash: [u8; 32] = hasher.result().into();
    let string_hash = hex::encode(hash);
    string_hash
}