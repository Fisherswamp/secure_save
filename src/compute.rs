use crate::data::UserInfo;
use getrandom;
use hex;
use sha2::{Digest, Sha256};

pub fn hash_and_salt(password: &String) -> UserInfo {
    let salt = generate_salt();
    hash_with_salt(password, &salt)
}

pub fn verify(password_to_check: &String, user_to_verify: &UserInfo) -> bool {
    let computed_hash =
        hash_with_salt(password_to_check, &((*user_to_verify).salt)).hashed_password;
    computed_hash == (*user_to_verify).hashed_password
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
        hashed_password: hash,
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

pub fn generate_salt() -> String {
    let salt_arr: &mut [u8] = &mut [0u8; 16];
    let status = getrandom::getrandom(salt_arr);
    status.unwrap();
    hex::encode(salt_arr)
}



