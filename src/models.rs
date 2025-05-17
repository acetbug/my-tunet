use std::env;

pub struct User {
    pub username: String,
    pub password: String,
}

impl User {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut args = env::args();
        args.next();
        Ok(Self {
            username: args.next().unwrap(),
            password: args.next().unwrap(),
        })
    }
}
