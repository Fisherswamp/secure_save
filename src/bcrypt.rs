use blowfish::Blowfish;
use base64;
use std::collections::HashMap;
use std::str;
use crate::compute;
use lazy_static;

lazy_static! {
	static ref RADIX64_TO_BASE64: HashMap<char, char> = {
		let conversion_map: HashMap<char, char> = Iterator::zip(
			"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".chars(),
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".chars()
		).collect();
		conversion_map
	};
	static ref BASE64_TO_RADIX64: HashMap<char, char> = {
		let conversion_map: HashMap<char, char> = Iterator::zip(
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".chars(),
			"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".chars()
		).collect();
		conversion_map
	};
}

pub fn bcrypt(cost: u8, password: &str) -> String {
	let salt = compute::generate_salt();
	bcrypt_with_salt(cost, &salt.as_bytes(), password)
}

pub fn bcrypt_with_salt(cost: u8, salt: &[u8], password: &str) -> String {
	let password_result = bcrypt_compute(cost, salt, password.as_bytes());
	let mut final_str = "$2y$".to_string();
	final_str.push_str(&format!("{:02}", cost));
	final_str.push_str("$");
	final_str.push_str(&u8_vec_to_radix_64(&salt.to_vec()));
	final_str.push_str(&password_result);
	final_str
}

fn bcrypt_compute(cost: u8, salt: &[u8], password: &[u8]) -> String {
    assert!(salt.len() == 16);
    assert!(!password.is_empty());
	assert!(!password.contains(&0u8));
	//null terminate password
	let mut nt_pword: Vec<u8> = Vec::new();
    nt_pword.extend_from_slice(password);
	nt_pword.push(0);
	//trunctuate password to 72 characters
	let truncated = {
		if nt_pword.len() > 72 { 
			&nt_pword[..72] 
		} else { 
			&nt_pword 
		}
	};
	let state = eks_blowfish_setup(cost, salt, truncated);
	let ctext_string = "OrpheanBeholderScryDoubt".to_string();
	//converting to 32 bit blocks, even tho algo calls for 64 bit blocks because of how blowfish encrypts
	let mut ctext_blocks = string_to_b32_arr(ctext_string);
	for block in 0..3 {
		let index = block*2;
		for _ in 0..64 {
			let encrpted_vals = state.bc_encrypt(ctext_blocks[index], ctext_blocks[index+1]);
			ctext_blocks[index] = encrpted_vals.0;
			ctext_blocks[index + 1] = encrpted_vals.1;
		}
	}
	//return result with last byte chopped off, because thats how it be
	let mut byte_array = b32_array_to_b8_vec(&ctext_blocks);
	byte_array.remove(23);
	u8_vec_to_radix_64(&byte_array)
}

fn u8_vec_to_radix_64(vec: &Vec<u8>) -> String {
	base64::encode(vec)
		.chars()
		.filter(|&val| {
			val != '='
		}).map(|val|{
			BASE64_TO_RADIX64.get(&val).unwrap()
		}).collect()
}

pub fn radix_64_to_u8(bcrypt_b64: &str) -> Vec<u8>{
	let mut regular_base64: String = bcrypt_b64.chars()
		.map(|val| {
			RADIX64_TO_BASE64.get(&val).unwrap()
		}).collect();
	let padding = 4 - bcrypt_b64.len() % 4;
	for _ in 0..padding {
		regular_base64.push_str("=");
	}
	base64::decode(regular_base64).unwrap()
}

fn string_to_b32_arr(string: String) -> [u32; 6] {
	let str_array = string.into_bytes();
	let mut text_blocks: [u32; 6] = [0u32; 6];
	for i in 0..str_array.len() {
		let index = i/4;
		let bitshift_amt = 8*(3-(i%4));
		text_blocks[index] += (str_array[i] as u32) << bitshift_amt;
	}
	text_blocks
}

fn b32_array_to_b8_vec(array: &[u32]) -> Vec<u8> {
	let mut converted_vec = Vec::new(); 
	for i in 0..array.len() {
		for j in 0..4 {
			let piece_to_grab: u8 = ((array[i] >> (8*(3-j))) & ((1 << 8)-1)) as u8;
			converted_vec.push(piece_to_grab);
		}
	}
	converted_vec
}

fn eks_blowfish_setup(cost: u8, salt: &[u8], password: &[u8]) -> Blowfish {
	assert!(cost < 32);
	assert!(cost >= 4);
	let mut blowfish_state = Blowfish::bc_init_state();
	blowfish_state.salted_expand_key(salt, password);
	let cost_iters = 1u32 << cost;
	for _ in 0..cost_iters {
		blowfish_state.bc_expand_key(password);
		blowfish_state.bc_expand_key(salt);
	}
	blowfish_state
}