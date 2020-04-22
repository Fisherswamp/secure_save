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

fn generate_salt() -> String {
    let salt_arr: &mut [u8] = &mut [0u8; 16];
    let status = getrandom::getrandom(salt_arr);
    status.unwrap();
    hex::encode(salt_arr)
}


pub struct BlowfishState {
    
}

fn bcrypt(cost: u8, salt: [u8; 16], password: Vec<u8>) {
    let state = eks_blowfish_setup(&cost, &salt, &password);
    let mut cypher_text = "OrpheanBeholderScryDoubt";//This string is hardcoded into the algo apparently
    for _ in 0..64 {
        cypher_text = encrypt_ecb(state, cypher_text);
    }
    return cypher_text;
}

fn eks_blowfish_setup(cost: &u8, salt: &[u8; 16], password: &Vec<u8>) {//expensive key setup
    let mut state = intial_state();
    state = expand_key(state, salt, password);
    let num_iterations = u32::pow(2, (*cost).into());
    for _ in 0..num_iterations {
        state = expand_key(state, 0, password);
        state = expand_key(state, 0, salt);
    }
    return state;
}

fn expand_key(state: BlowfishState, salt: &[u8; 16], password: &Vec<u8>) -> BlowfishState{
    let length = password.len();
    //convert password from u8 to u32
    let mut p_array: Vec<u32> = Vec::new();
    let mut num_size = 0;
    let mut building_num: u32 = 0;
    for password_byte_index in 0..password.len() {
        if num_size >= 4 {
            p_array.push(building_num);
            building_num = 0;
            num_size = 0;
        }
        let adding_chunk: u32 = (*password)[password_byte_index].into();
        building_num = (building_num << 4) + adding_chunk;
        num_size = num_size + 1;
    }
    //
    for n in 1..18 {
        let index = 4*(n-1);        
        p_array[n] = p_array[n] ^  p_array[index];
    }
    BlowfishState {

    }
}


