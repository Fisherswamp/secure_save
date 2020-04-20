pub extern crate sha2;
pub extern crate hex;

mod compute;

fn main() {
    let hashme: String = "Hello ,world!".to_string();
    compute::hash_and_salt(&hashme);
}
