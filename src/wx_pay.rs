use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use anyhow::bail;
use chrono::Utc;
use crypto::common::generic_array::GenericArray;
use rand::{distributions::Alphanumeric, Rng};
use reqwest::{
    header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT},
    StatusCode,
};
use rsa::{pkcs8::DecodePrivateKey, Hash, PaddingScheme, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;

#[cfg(not(test))]
use log::{debug, info, warn}; // Use log crate when building application
#[cfg(test)]
use std::{println as debug, println as info, println as warn, println as error}; // Workaround to use prinltn! for logs.

#[derive(Debug, Clone)]
pub struct WxPay {
    appid: String,
    mchid: String,
    private_key: String,
    serial_no: String,
    apiv3_private_key: String,
    notify_url: String,
    certificates: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct WxData {
    pub sign_type: String,
    pub pay_sign: String,
    pub prepay_id: String,
    pub nonce_str: String,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Amount {
    pub total: u32,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Payer {
    pub openid: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum PayType {
    App,
    Mini,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PayParams {
    pub pay_type: PayType,
    pub description: String,
    pub out_trade_no: String,
    pub amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<Payer>,
}

#[derive(Clone)]
struct ApiBody {
    url: String,
    method: Method,
    pathname: String,
}
#[derive(Clone)]
enum Method {
    GET,
    POST,
}

/// 微信支付，回调解密
#[derive(Serialize, Deserialize, Debug)]
pub struct WxNotifyData {
    pub mchid: String,
    pub appid: String,
    pub out_trade_no: String,
    pub transaction_id: String,
    pub trade_type: String,
    pub trade_state: String,
    pub trade_state_desc: String,
    pub bank_type: String,
    pub attach: String,
    pub success_time: String,
    pub payer: Payer,
    pub amount: WxNotifyDataAmount,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct WxNotifyDataAmount {
    pub total: u32,
    pub payer_total: u32,
    pub currency: String,
    pub payer_currency: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct WxPayNotifyResource {
    pub algorithm: String,
    pub associated_data: String,
    pub ciphertext: String,
    pub nonce: String,
    pub original_type: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct WxPayNotify {
    pub create_time: String,
    pub event_type: String,
    pub id: String,
    pub resource: WxPayNotifyResource,
    pub resource_type: String,
    pub summary: String,
}

#[derive(Serialize, Deserialize, Debug)]
// #[serde(deny_unknown_fields)]
pub struct WxOrderRes {
    trade_state: String,
    trade_state_desc: String,
}

fn rand_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(len)
        .map(char::from)
        .collect::<String>()
}

impl WxPay {
    pub fn new(
        appid: &str,
        mchid: &str,
        private_key: &str,
        serial_no: &str,
        apiv3_private_key: &str,
        notify_url: &str,
        certificates: Option<String>,
    ) -> Self {
        WxPay {
            appid: appid.to_string(),
            mchid: mchid.to_string(),
            private_key: private_key.to_string(),
            serial_no: serial_no.to_string(),
            apiv3_private_key: apiv3_private_key.to_string(),
            notify_url: notify_url.to_string(),
            certificates,
        }
    }

    fn sign(&self, content: &str, privite_key: &str) -> Result<String, anyhow::Error> {
        // SHA256withRSA 编码
        let mut hasher = sha2::Sha256::new();
        hasher.update(content.as_bytes());
        let res = hasher.finalize();
        debug!("res:{:?}", res);
        let pkey = RsaPrivateKey::from_pkcs8_pem(&privite_key)?;
        let signature = pkey.sign(
            PaddingScheme::PKCS1v15Sign {
                hash: Option::from(Hash::SHA2_256),
            },
            res.as_slice(),
        )?;
        return Ok(base64::encode(signature));
    }

    fn get_headers(
        &self,
        api_body: &ApiBody,
        params_string: &str,
    ) -> Result<HeaderMap, anyhow::Error> {
        let dt = Utc::now();
        let timestamp = dt.timestamp();
        let onece_str = rand_string(32);
        let method = match api_body.method {
            Method::GET => "GET",
            Method::POST => "POST",
        };

        let content = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            method, api_body.pathname, timestamp, onece_str, params_string
        );
        // 获取签名
        let signature = self.sign(&content, &self.private_key)?;

        // 组装header
        let authorization = format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{mchid}",serial_no="{serialNo}",nonce_str="{nonceStr}",timestamp="{timeStamp}",signature="{signature}""#,
            mchid = self.mchid,
            serialNo = self.serial_no,
            nonceStr = onece_str,
            timeStamp = timestamp,
            signature = signature
        );

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json; charset=utf-8".parse()?);
        headers.insert(ACCEPT, "application/json".parse()?);
        headers.insert(AUTHORIZATION, authorization.parse()?);
        headers.insert(USER_AGENT, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.71".parse()?);

        Ok(headers)
    }

    /// 微信支付
    fn pay(&self, params: PayParams) -> Result<WxData, anyhow::Error> {
        debug!("aaaj jsapi {}", &self.appid);

        if params.pay_type == PayType::Mini && params.payer.is_none() {
            bail!("微信小程序支付必须提供payer.openid");
        }
        // debug!("aaaj jsapi {:#?}", params.payer.openid);

        #[derive(Serialize, Deserialize)]
        struct RequestParam {
            description: String,
            out_trade_no: String,
            amount: Amount,
            #[serde(skip_serializing_if = "Option::is_none")]
            payer: Option<Payer>,
            appid: String,
            mchid: String,
            notify_url: String,
        }

        let req_param = RequestParam {
            description: params.description,
            out_trade_no: params.out_trade_no,
            amount: params.amount,
            payer: params.payer,
            appid: self.appid.clone(),
            mchid: self.mchid.clone(),
            notify_url: self.notify_url.clone(),
        };

        let req_param_str = serde_json::to_string(&req_param)?;

        debug!("req_param_str:{}", req_param_str);
        let api_body = match params.pay_type {
            PayType::App => ApiBody {
                url: "https://api.mch.weixin.qq.com/v3/pay/transactions/app".to_string(),
                method: Method::POST,
                pathname: "/v3/pay/transactions/app".to_string(),
            },
            PayType::Mini => ApiBody {
                url: "https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi".to_string(),
                method: Method::POST,
                pathname: "/v3/pay/transactions/jsapi".to_string(),
            },
        };

        let headers_all = self.get_headers(&api_body, &req_param_str)?;

        #[derive(Serialize, Deserialize, Debug)]
        struct PaySuccessRes {
            prepay_id: String,
        }
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(&api_body.url)
            .headers(headers_all)
            .json(&req_param)
            .send()?;

        match res.status() {
            StatusCode::FORBIDDEN => {
                log::error!("交易错误:{:?}", res.text());
                bail!("交易错误，请检查 订单号是否重复，商户是否有权限")
            }
            StatusCode::INTERNAL_SERVER_ERROR => {
                log::error!("系统错误:{:?}", res.text());
                bail!("系统错误")
            }

            StatusCode::UNAUTHORIZED => {
                log::error!("签名错误:{:?}", res.text());
                bail!("签名错误	")
            }

            _ => {}
        }

        let pre_data = res.text()?;
        debug!("pre_data:{:#?}", pre_data);
        let pre_data: PaySuccessRes = match serde_json::from_str(&pre_data) {
            Ok(v) => v,
            Err(e) => {
                let v: Value = serde_json::from_str(&pre_data)?;
                bail!(v["message"]
                    .as_str()
                    .unwrap_or(e.to_string().as_str())
                    .to_string());
            }
        };
        let ran_str = rand_string(32);
        //  package: `prepay_id=${JSON.parse(preData.data).prepay_id}`,
        let pack = "prepay_id=".to_string() + pre_data.prepay_id.as_str();
        let dt = Utc::now();
        let now_time = dt.timestamp();

        let content = self.appid.to_string()
            + "\n"
            + now_time.to_string().as_str()
            + "\n"
            + ran_str.as_str()
            + "\n"
            + pack.as_str()
            + "\n";

        // 获取签名
        let pay_si = self.sign(&content, &self.private_key)?;

        let wx_data = WxData {
            sign_type: "RSA".into(),
            pay_sign: pay_si,
            prepay_id: pre_data.prepay_id,
            nonce_str: ran_str,
            timestamp: now_time.to_string(),
        };

        Ok(wx_data)
    }

    pub fn wx_pay(
        &self,
        pay_type: PayType,
        description: &str,
        out_trade_no: &str,
        total: u32,
        openid: Option<String>,
    ) -> Result<WxData, anyhow::Error> {
        let params = PayParams {
            pay_type,
            description: description.to_string(),
            out_trade_no: out_trade_no.to_string(),
            amount: Amount { total },
            payer: openid.map(|v| Payer { openid: v }),
        };
        log::debug!("params:{:#?}", params);
        let wx_data = self.pay(params)?;
        Ok(wx_data)
    }

    /// 微信支付订单号查询
    /// https://api.mch.weixin.qq.com/v3/pay/transactions/id/{transaction_id}
    pub fn transactions_out_trade_no(
        &self,
        out_trade_no: &str,
    ) -> Result<WxOrderRes, anyhow::Error> {
        let api_body = ApiBody {
            url: format!(
                "https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/{}?mchid={}",
                out_trade_no, self.mchid
            ),
            method: Method::GET,
            pathname: format!(
                "/v3/pay/transactions/out-trade-no/{}?mchid={}",
                out_trade_no, self.mchid
            ),
        };
        let client = reqwest::blocking::Client::new();

        let headers_all = self.get_headers(&api_body, "")?;
        let res = client
            .get(api_body.url.clone())
            .headers(headers_all)
            .send()?;

        match res.status() {
            StatusCode::NOT_FOUND => {
                log::error!("订单不存在:{:?}", res.text());
                bail!("订单不存在")
            }
            StatusCode::BAD_REQUEST => {
                log::error!("签名错误：{:?}", res.text());
                bail!("订单已关闭")
            }
            StatusCode::UNAUTHORIZED => {
                log::error!("签名错误：{:?}", res.text());
                bail!("签名错误")
            }
            StatusCode::FORBIDDEN => {
                log::error!("交易错误:{:?}", res.text());
                bail!("交易错误")
            }
            StatusCode::TOO_MANY_REQUESTS => {
                log::error!("频率超限:{:?}", res.text());
                bail!("频率超限")
            }
            StatusCode::INTERNAL_SERVER_ERROR => {
                log::error!("订单号非法:{:?}", res.text());
                bail!("订单号非法 或 系统错误 或 银行系统异常")
            }
            _ => {}
        };

        let order_res: WxOrderRes = res.json()?;
        debug!("order_res:{:#?}", order_res);

        Ok(order_res)
    }

    /// 微信支付，回调解密
    pub fn decode_wx(&self, params: WxPayNotify) -> Result<WxNotifyData, anyhow::Error> {
        let auth_key_length = 16;

        let mut t_key = [0u8; 32];
        hex::decode_to_slice(
            hex::encode(&self.apiv3_private_key),
            &mut t_key as &mut [u8],
        )?;
        let key = GenericArray::from_slice(&t_key);

        let mut t_nonce = [0u8; 12];
        hex::decode_to_slice(
            hex::encode(params.resource.nonce.clone()),
            &mut t_nonce as &mut [u8],
        )?;
        let nonce = GenericArray::from_slice(&t_nonce);

        let t_ciphertext_base = base64::decode(params.resource.ciphertext.clone())?;
        let cipherdata_length = t_ciphertext_base.len() - auth_key_length;

        let cipherdata = &t_ciphertext_base[0..cipherdata_length];
        let auth_tag = &t_ciphertext_base[cipherdata_length..];

        let mut ciphertext = Vec::from(cipherdata);
        ciphertext.extend_from_slice(&auth_tag);

        let mut t_add = [0u8; 11]; // 这里可能会根据返回值 associated_data 长度而不同，目前应该是固定为 "transaction" 。
        hex::decode_to_slice(
            hex::encode(params.resource.associated_data.clone()),
            &mut t_add as &mut [u8],
        )?;
        let payload = Payload {
            msg: &ciphertext,
            aad: &t_add,
        };
        let cipher = Aes256Gcm::new(key);
        let plaintext = match cipher.decrypt(nonce, payload) {
            Ok(v) => v,
            Err(e) => bail!("解密失败:{:?}", e),
        };
        let content = std::str::from_utf8(&plaintext)?;
        let data: WxNotifyData = serde_json::from_str(content)?;

        Ok(data)
    }
}

#[cfg(test)]
mod test {
    use std::fs;

    use super::{Payer, WxPay};
    use std::{println as debug, println as info, println as warn, println as error};

    #[test]
    fn test_jsapi() {
        let key = fs::read_to_string("d:/data/cert/apiclient_key.pem").unwrap();
        let pay = WxPay::new(
            "wx9b0ca8695776f224",
            "1629824688",
            &key,
            "7CB273D2C44A54E21992BEBAF72C0321D40EEB38",
            "8497b6e0ff86bb6288badd19444855cd",
            "https://api.uchu360.com/notify",
            None,
        );

        let params = super::PayParams {
            pay_type: crate::wx_pay::PayType::Mini,
            description: "xxx".to_string(),
            out_trade_no: "8888888888".to_string(),
            amount: super::Amount { total: 1 },
            payer: Some(Payer {
                openid: "xxxxxx".to_string(),
            }),
        };
        let res = pay.pay(params);
        debug!("res:{:#?}", res);

        // app
        let params = super::PayParams {
            pay_type: crate::wx_pay::PayType::App,
            description: "xxx".to_string(),
            out_trade_no: "8888888888".to_string(),
            amount: super::Amount { total: 1 },
            payer: None,
        };

        let res = pay.pay(params);
        debug!("res:{:#?}", res);

        let res = pay.transactions_out_trade_no("9999999999");
        debug!("res:{:#?}", res);
    }
}
