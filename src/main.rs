mod compute;
mod data;

fn main() {
    let hashme: String = "Hello, world!".to_string();
    let user = compute::hash_and_salt(&hashme);
    println!("{}", user);
    println!("Verified password: {}", compute::verify(&hashme, &user));
}
