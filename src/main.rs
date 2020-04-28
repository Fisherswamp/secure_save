#[macro_use]
extern crate lazy_static;
mod compute;
mod data;
mod bcrypt;
mod tester;

fn main() {
    let hashme: String = "Hello, world!".to_string();
    let user = compute::hash_and_salt(&hashme);
    println!("{}", user);
    println!("Verified password: {}", compute::verify(&hashme, &user));
    println!("-----------------");
    let salt = vec![38, 113, 212, 141, 108, 213, 195, 166,
        201, 38, 20, 13, 47, 40, 104, 18];
    let result = bcrypt::bcrypt_with_salt(5, &salt, &"My S3cre7 P@55w0rd!".to_string());
    println!("{}", result);
}
