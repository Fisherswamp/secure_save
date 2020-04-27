use blowfish::Blowfish;
use base64;
use std::collections::HashMap;
use std::str;
use crate::compute;

pub fn bcrypt(cost: u8, password: &String) -> String {
	let salt = compute::generate_salt();
	bcrypt_with_salt(cost, salt.as_bytes(), &password)
}

pub fn bcrypt_with_salt(cost: u8, salt: &[u8], password: &String) -> String {
	let password_result = bcrypt_compute(cost, salt, &password.as_bytes());
	let mut final_str = "$2$".to_string();
	final_str.push_str(&cost.to_string());
	final_str.push_str("$");
	final_str.push_str(&u8_vec_to_radix_64(&salt.to_vec()));
	final_str.push_str(&password_result);
	final_str
}

fn bcrypt_compute(cost: u8, salt: &[u8], password: &[u8]) -> String {
    assert!(salt.len() == 16);
    assert!(!password.is_empty() && password.len() <= 72);
	assert!(!password.contains(&0u8));
	//null terminate password
	let mut nt_pword: Vec<u8> = Vec::new();
    nt_pword.extend_from_slice(password);
	nt_pword.push(0);
	//trunctuate password to 72
	let truncated = if nt_pword.len() > 72 { &nt_pword[..72] } else { &nt_pword };
	let state = ekc_blowfish_setup(cost, salt, truncated);
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
	u8_vec_to_radix_64(&b32_array_to_b8_vec(&ctext_blocks))
}
//I know this creates the map every time it is called, this is just a proof of concept anyways
fn u8_vec_to_radix_64(vec: &Vec<u8>) -> String {
	let bcrypt_base64_alphabet: Vec<char> = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
	let regular_base64_alphabet: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".chars().collect();
	let mut conversion_map: HashMap<char, char> = HashMap::new();
	let mut result = "".to_string();
	for i in 0..64 {
		conversion_map.insert(regular_base64_alphabet[i], bcrypt_base64_alphabet[i]);
	}
	let regular_64_of_input = base64::encode(vec);
	for character in regular_64_of_input.chars() {
		if character == '=' {
			break;
		}
		result.push_str(&conversion_map.get(&character).unwrap().to_string());
	}
	result
}

fn string_to_b32_arr(string: String) -> [u32; 6] {
	let str_array = string.into_bytes();
	let mut text_blocks: [u32; 6] = [0u32; 6];
	for i in 0..str_array.len() {
		let index = i/4;
		let bitshift_amt = 8*(3-(i%4));
		text_blocks[index] = text_blocks[index] + ((str_array[i] as u32) << bitshift_amt);
	}
	//test to make sure is correct bit manip
	//should be: 0x4F727068, 0x65616E42, 0x65686F6C, 0x64657253, 0x63727944, 0x6F756274‬
	//println!("Ctext_in_blocks: {} {} {}", text_blocks[0].to_string(), 
	//	text_blocks[1].to_string(), text_blocks[2].to_string());
	text_blocks
}

fn b32_array_to_b8_vec(array: &[u32]) -> Vec<u8> {
	let mut converted_vec = Vec::new(); 
	for i in 0..array.len() {
		for j in 0..4 {
			//I know there's a more efficient way to do this, but I already did it this way
			let piece_to_grab: u8 = ((array[i] >> (8*(3-j))) & ((1 << 8)-1)) as u8;
			converted_vec.push(piece_to_grab);
		}
	}
	converted_vec
} 
#[cfg(test)]
#[test]
fn test_conversions() {
	let start_string = "hello world".to_string();
	let array_32 = string_to_b32_arr(start_string);
	let vec_8 = b32_array_to_b8_vec(&array_32);
	let string_back_at_it: String = str::from_utf8(&vec_8).unwrap().to_string();
	println!("Result: {}", string_back_at_it);
	let rust_b64 = u8_vec_to_radix_64(&"hello world".as_bytes().to_vec());
	println!("Result b64 rust: {}", rust_b64);
}

fn ekc_blowfish_setup(cost: u8, salt: &[u8], password: &[u8]) -> Blowfish {
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