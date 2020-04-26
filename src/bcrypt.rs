use blowfish::Blowfish;

fn bcrypt(cost: u8, salt: &[u8], password: &[u8]) {
    assert!(salt.len() == 16);
    assert!(!password.is_empty() && password.len() <= 72);
	let state = ekc_blowfish_setup(cost, salt, password);
	let ctext_string = "OrpheanBeholderScryDoubt".to_string();
	let ctext = ctext_string.into_bytes();
	print!("ctext: {}", ctext)
}

fn ekc_blowfish_setup(cost: u8, salt: &[u8], password: &[u8]) -> Blowfish {
	assert!(cost < 32);
	assert!(cost >= 4);
	let mut blowfish_state = Blowfish::bc_init_state();
	state.salted_expand_key(salt, password);
	let cost_iters = 1u32 << cost;
	for _ in 0..cost_iters {
		state.bc_expand_key(password);
		state.bc_expand_key(salt);
	}
	state
}