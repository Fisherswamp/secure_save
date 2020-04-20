use std::fmt;

pub struct UserInfo {
    pub hashed_password: String,
    pub salt: String,
}

impl fmt::Display for UserInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Password: {}\nSalt: {}", self.hashed_password, self.salt)
    }
}