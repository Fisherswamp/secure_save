mod compute;

fn main() {
    let hashme: String = "Hello ,world!".to_string();
    compute::hash_and_salt(&hashme);
}
