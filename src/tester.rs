#![cfg(test)]
use crate::{compute, bcrypt};
use std::collections::HashMap;

#[test]
fn test_compute() {
    let test_passwords = ["howdy", "hunter2", "I_am_legend89", "2fast4u", "34qyuridhfsgy4q3rq43yrwh"];
    for pass in test_passwords.iter() {
        let password = pass.to_string();
        let hash_and_salt = compute::hash_and_salt(&password);
        assert!(compute::verify(&password, &hash_and_salt));//passes on correct password
        assert!(!compute::verify(&format!("{}{}", pass, "."), &hash_and_salt));//fails on incorrect passsword
        let mut second_hash = compute::hash_and_salt(&password);
        second_hash.salt = hash_and_salt.salt;//replace salt but keep hash
        assert!(!compute::verify(&password, &second_hash));//This should now fail since the salt is different
    }
}
#[test]
//using https://bcrypt-generator.com/ to check correct results
fn test_bcrypt() {
    let mut password_to_hash: HashMap<&str, &str> = HashMap::new();
    password_to_hash.insert("My main man, obama", "$2y$12$ifdZVwfe/znzq4qBU.sCUudVbw9PHSS1Eyswr8mlkC6W6l24i6XUC");
    password_to_hash.insert("Red lipstick", "$2y$06$Ry8xUj0OyK92baKIYAXb7OvZFxvM8b/m28G/3KChkPJEu5gQJlAWi");
    password_to_hash.insert("hunter2", "$2y$13$1/ICuYv88WbSliqs7HiGlODB0O9DeSfuJXJ8swQKQasbFeQKe228q");
    password_to_hash.insert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "$2y$13$BC6w2tXXKqHGjcjtY1xvouNuS.v5PSfcZo7sYuh5CYmFv3u8Btnc2"    
    );
    for password in password_to_hash.keys() {
        let result_should_be = *password_to_hash.get(password).unwrap();
        let cost_vals: (char, char) = (result_should_be.chars().nth(4).unwrap(), 
            result_should_be.chars().nth(5).unwrap());
        let cost: u8 = ((cost_vals.0.to_digit(10).unwrap() * 10) 
            + (cost_vals.1.to_digit(10).unwrap())) as u8; 
        let bcrypt_salt = result_should_be[7..29].to_string();
        let salt = bcrypt::radix_64_to_u8(&bcrypt_salt);
        let result = bcrypt::bcrypt_with_salt(cost, &salt, password);
        assert_eq!(result, result_should_be);
    }
    let bcrypt_fail_hash = "$2y$08$x.ozg1ekyXtjXOefw8VoBeEHWhLf/g3Qj5ggvvHXfhJySv/ZkcYZ.";
    let password = "blueblueblue";//this is wrong, actual password is redredred
    let result = bcrypt::bcrypt_with_salt(8, &bcrypt::radix_64_to_u8("x.ozg1ekyXtjXOefw8VoBe"), password);
    assert_ne!(result, bcrypt_fail_hash);

}