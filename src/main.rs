mod compute;
mod data;
mod bcrypt;

fn main() {
    let hashme: String = "Hello, world!".to_string();
    let user = compute::hash_and_salt(&hashme);
    println!("{}", user);
    println!("Verified password: {}", compute::verify(&hashme, &user));
    println!("-----------------");
    let salt = hex::decode(compute::generate_salt()).unwrap();
    let password = [0u8; 72];
    bcrypt::bcrypt(5u8, &salt, &password);
}
