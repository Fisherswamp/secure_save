use crate::{compute, bcrypt};

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
    
    let result_should_be = "$2y$12$ifdZVwfe/znzq4qBU.sCUudVbw9PHSS1Eyswr8mlkC6W6l24i6XUC".to_string();
    let salt = bcrypt::radix_64_to_u8(&"ifdZVwfe/znzq4qBU.sCUu".to_string());
    let result = bcrypt::bcrypt_with_salt(12, &salt, "My main man, obama");
    assert_eq!(result, result_should_be);
}