mod cli;
mod creds;
mod digest;
mod encrypt;
mod web;

use std::error::Error;

use clap::Parser;

use crate::{
    cli::{Cli, Commands},
    creds::Credentials,
    digest::{hmac_md5_digest, sha1_digest},
    encrypt::encode,
    web::LoginClient,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Set { username, password }) => {
            let creds = Credentials {
                username: username.clone(),
                password: password.clone(),
            };
            creds.store()?;
            println!("Credentials stored successfully.");
        }
        Some(Commands::Show) => {
            let creds = Credentials::retrieve()?;
            println!("Username: {}", creds.username);
        }
        None => {
            let creds = Credentials::retrieve()?;
            let client = LoginClient::new();
            let ac_id = client.get_ac_id().await?;
            let token = client.get_challenge(&creds.username).await?;
            let password_md5 = hmac_md5_digest(&token);
            let info = encode(&creds, ac_id, &token)?;
            let chksum = sha1_digest(format!(
                "{0}{1}{0}{2}{0}{3}{0}{0}200{0}1{0}{4}",
                token, creds.username, password_md5, ac_id, info
            ));
            client
                .login(
                    &ac_id,
                    &creds.username,
                    &format!("{{MD5}}{}", password_md5),
                    &info,
                    &chksum,
                )
                .await?;
            println!("Login successful.");
        }
    }

    Ok(())
}
