mod digest;
mod encrypt;
mod models;
mod web;

use std::error::Error;

use digest::{hmac_md5_digest, sha1_digest};
use models::User;
use web::LoginClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let user = User::new()?;
    let client = LoginClient::new();
    let ac_id = client.get_ac_id().await?;
    let token = client.get_challenge(&user.username).await?;
    let password_md5 = hmac_md5_digest(&token);
    let info = encrypt::encode(&user, ac_id, &token)?;
    let chksum = sha1_digest(format!(
        "{0}{1}{0}{2}{0}{3}{0}{0}200{0}1{0}{4}",
        token, user.username, password_md5, ac_id, info
    ));
    client
        .login(
            &ac_id,
            &user.username,
            &format!("{{MD5}}{}", password_md5),
            &info,
            &chksum,
        )
        .await
}
