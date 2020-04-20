use sha2::{Sha256, Digest};
use hex;
use getrandom;
use crate::data::UserInfo;


pub fn hash_and_salt(password: &String) -> UserInfo {
    let salt = generate_salt();
    hash_with_salt(password, &salt)
}

fn hash_with_salt(password: &String, salt: &String) -> UserInfo {
    let mut salted_pass = password.clone();
    salted_pass.push_str(salt);
    let mut hash = calculate_hash(&salted_pass);
    for _ in 0..100 {
        hash.push_str(salt);
        hash = calculate_hash(&hash);
    }
    UserInfo {
        hashed_password: hash.clone(),
        salt: salt.clone(),
    }
}

fn calculate_hash(object_to_hash: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.input(object_to_hash);
    let hash: [u8; 32] = hasher.result().into();
    let string_hash = hex::encode(hash);
    string_hash
}

fn generate_salt() -> String {
    let salt_arr: &mut [u8] =  &mut[0u8; 16];
    let status = getrandom::getrandom(salt_arr);
    if status.is_ok() {
        let salt_hex = hex::encode(salt_arr);
        salt_hex
    } else {
        status.unwrap();
        hex::encode(salt_arr)
    }
}