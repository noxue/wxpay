// use anyhow::{bail, Ok};
// use chrono::Utc;
// use rand::{distributions::Alphanumeric, Rng};
// use rsa::{pkcs8::DecodePrivateKey, Hash, PaddingScheme, RsaPrivateKey};
// use sha2::Digest;
// use std::fs::{self, File};

pub mod wx_pay;
mod constants;

// fn sign(content: &str, privite_key: &str) -> Result<String, anyhow::Error> {
//     // SHA256withRSA 编码
//     let mut hasher = sha2::Sha256::new();
//     hasher.update(content.as_bytes());
//     let res = hasher.finalize();
//     println!("res:{:?}", res);
//     let pkey = RsaPrivateKey::from_pkcs8_pem(&privite_key)?;
//     let signature = pkey
//         .sign(
//             PaddingScheme::PKCS1v15Sign {
//                 hash: Option::from(Hash::SHA2_256),
//             },
//             res.as_slice(),
//         )
//         .unwrap();
//     return Ok(base64::encode(signature));
// }

// fn certificates() -> Result<String, anyhow::Error> {
//     let nonce = rand::thread_rng()
//         .sample_iter(Alphanumeric)
//         .take(16)
//         .map(char::from)
//         .collect::<String>();
//     // 发起http请求
//     let client = reqwest::blocking::Client::new();
//     let dt = Utc::now();
//     let timestamp = dt.timestamp();

//     // 16位随机字符串
//     let nonce = rand::thread_rng()
//         .sample_iter(Alphanumeric)
//         .take(16)
//         .map(char::from)
//         .collect::<String>();
//     // println!("nonce:{}", nonce);
//     let method = "GET";
//     let url = "/v3/certificates";
//     let body = "";

//     let msg = format!("{}\n{}\n{}\n{}\n{}\n", method, url, timestamp, nonce, body);

//     println!("msg:{}", msg);

//     // 读取文件 apiclient_cert.pem
//     let key = fs::read_to_string("./cert/apiclient_key.pem")?;
//     // println!("key:{}", key);

//     let signature = format!(
//         r#"WECHATPAY2-SHA256-RSA2048 mchid="{mchid}",serial_no="{serialNo}",nonce_str="{nonceStr}",timestamp="{timeStamp}",signature="{signature}""#,
//         mchid = "1629824688",
//         serialNo = "7CB273D2C44A54E21992BEBAF72C0321D40EEB38",
//         nonceStr = nonce,
//         timeStamp = chrono::Local::now().timestamp(),
//         signature = sign(&msg, &key)?
//     );
//     println!("signature:{}", signature);
//     let res = client
//         .get("https://api.mch.weixin.qq.com/v3/certificates")
//         .header("Authorization", signature)
//         .header("Accept", "*/*")
//         .header("User-Agent", "PostmanRuntime/7.28.4")
//         .header("Content-Type", "application/json")
//         .send()?;
//     println!("res:{}", res.text()?);
//     Ok("".to_string())
// }

// #[cfg(test)]
// mod tests {
//     use chrono::Utc;

//     #[test]
//     fn test_sign() {
//         // let dt = Utc::now();
//         // let timestamp = dt.timestamp();
//         // let result = super::sign("GET", "/v3/certificates", "", timestamp);
//         // println!("result:{}", result.unwrap());
//     }

//     #[test]
//     fn test_certificates() {
//         super::certificates().unwrap();
//     }
// }
