use blowfish::Blowfish;
use byteorder::{BE};
use std::str;

pub fn bcrypt(cost: u8, salt: &[u8], password: &[u8]) {
    assert!(salt.len() == 16);
    assert!(!password.is_empty() && password.len() <= 72);
	let state = ekc_blowfish_setup(cost, salt, password);
	let ctext_string = "OrpheanBeholderScryDoubt".to_string();
	//converting to 32 bit blocks, even tho algo calls for 64 bit blocks because of how blowfish encrypts
	let mut ctext_blocks = string_to_b32_arr(ctext_string);
	let mut output = [0u8; 24];
	for block in 0..ctext_blocks.len() {
		let index = block*2;
		for _ in 0..64 {
			let encrpted_vals = state.bc_encrypt(ctext_blocks[index], ctext_blocks[index+1]);
			ctext_blocks[index] = encrpted_vals.0;
			ctext_blocks[index + 1] = encrpted_vals.1;
		}
	}
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
	let mut convertedVec = Vec::new(); 
	for i in 0..array.len() {
		for j in 0..4 {
			//I know there's a more efficient way to do this, but it works so :P
			let pieceToGrab: u8 = ((array[i] & ((1 << 8)-1) << (8*(3-j))) >> (8*(3-j))) as u8;
			convertedVec.push(pieceToGrab);
		}
	}
	convertedVec
} 
#[cfg(test)]
#[test]
fn test_conversions() {
	let start_string = "OrpheanBeholderScryDoubt".to_string();
	let array_32 = string_to_b32_arr(start_string);
	let vec_8 = b32_array_to_b8_vec(&array_32);
	let string_back_at_it: String = str::from_utf8(&vec_8).unwrap().to_string();
	println!("Result: {}", string_back_at_it);
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