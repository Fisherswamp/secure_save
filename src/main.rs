pub extern crate sha2;
pub extern crate hex;
pub extern crate rand;

mod compute;

fn main() {
    let hashme: String = "Hello ,world!".to_string();
    compute::hash_and_salt(&hashme);
}
