use std::error::Error;

use regex::Regex;
use reqwest::{Client, ClientBuilder};

pub struct LoginClient {
    client: Client,
}

impl LoginClient {
    pub fn new() -> Self {
        Self {
            client: ClientBuilder::new()
                .no_proxy()
                .build()
                .unwrap(),
        }
    }

    pub async fn get_ac_id(&self) -> Result<u32, Box<dyn Error>> {
        let res = self
            .client
            .get("http://www.tsinghua.edu.cn/")
            .send()
            .await?;
        let body = res.text().await?;
        let re = Regex::new(r"index_(\d+)\.html").unwrap();
        match re.captures(&body) {
            Some(caps) => Ok(caps[1].parse::<u32>().unwrap()),
            None => Err("Failed to find ac_id in response body".into()),
        }
    }

    pub async fn get_challenge(&self, username: &str) -> Result<String, Box<dyn Error>> {
        let params = [("username", username), ("callback", "callback")];
        let res = self
            .client
            .get("https://auth4.tsinghua.edu.cn/cgi-bin/get_challenge")
            .query(&params)
            .send()
            .await?;
        let body = res.text().await?;
        let re = Regex::new(r"\w{64}").unwrap();
        match re.captures(&body) {
            Some(caps) => Ok(caps[0].to_string()),
            None => Err("Failed to find challenge in response body".into()),
        }
    }

    pub async fn login(
        &self,
        ac_id: &u32,
        username: &str,
        password_md5: &str,
        info: &str,
        chksum: &str,
    ) -> Result<(), Box<dyn Error>> {
        let params = [
            ("action", "login"),
            ("ac_id", &ac_id.to_string()),
            ("n", "200"),
            ("type", "1"),
            ("username", username),
            ("password", password_md5),
            ("info", info),
            ("chksum", chksum),
        ];
        self.client
            .post("https://auth4.tsinghua.edu.cn/cgi-bin/srun_portal")
            .form(&params)
            .send()
            .await?;
        Ok(())
    }
}
