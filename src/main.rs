mod compute;
mod data;

fn main() {
    let hashme: String = "Hello, world!".to_string();
    println!("{}", compute::hash_and_salt(&hashme));
}
