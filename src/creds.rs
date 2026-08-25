use serde::{Deserialize, Serialize};

const SERVICE_NAME: &str = "my-tunet";
const KEYCHAIN_ACCOUNT: &str = "credentials";

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Credentials {
    pub fn store(&self) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = serde_json::to_string(self)?;
        let entry = Self::get_entry()?;
        entry.set_password(&serialized)?;
        Ok(())
    }

    pub fn retrieve() -> Result<Self, Box<dyn std::error::Error>> {
        let entry = Self::get_entry()?;
        let serialized = entry.get_password()?;
        let creds = serde_json::from_str(&serialized)?;
        Ok(creds)
    }

    fn get_entry() -> Result<keyring::Entry, Box<dyn std::error::Error>> {
        Ok(keyring::Entry::new(SERVICE_NAME, KEYCHAIN_ACCOUNT)?)
    }
}
