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
use log::debug;
#[cfg(test)]
use std::{println as debug, println as info, println as warn, println as error};

#[derive(Debug, Clone)]
pub struct WxPay {
    pub mchid: String,             // 商户编号
    pub private_key: String,       // 秘钥文件apiclient_key.pem中的内容
    pub serial_no: String,         // 证书序列号
    pub apiv3_private_key: String, // apiv3秘钥
    pub notify_url: String,        // 通知地址
}

#[derive(Serialize, Deserialize, Debug)]
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
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Payer {
    pub openid: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum PayType {
    App,
    JsApi,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PayParams {
    // appid 不同场景下使用不同的id，
    // 比如小程序使用小程序appid，app支付使用app应用的appid，公众号使用公众号appid
    pub appid: String,
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
#[derive(Serialize, Deserialize, Debug, Default)]
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
#[derive(Serialize, Deserialize, Debug, Default)]
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
    pub trade_state: String,
    pub trade_state_desc: String,
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
        mchid: &str,
        private_key: &str,
        serial_no: &str,
        apiv3_private_key: &str,
        notify_url: &str,
    ) -> Self {
        WxPay {
            mchid: mchid.to_string(),
            private_key: private_key.to_string(),
            serial_no: serial_no.to_string(),
            apiv3_private_key: apiv3_private_key.to_string(),
            notify_url: notify_url.to_string(),
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
    async fn pay(&self, params: PayParams) -> Result<WxData, anyhow::Error> {
        if params.pay_type == PayType::JsApi && params.payer.is_none() {
            bail!("JSAPI支付必须提供 payer.openid 参数");
        }
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
            appid: params.appid.clone(),
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
            PayType::JsApi => ApiBody {
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
        let client = reqwest::Client::new();
        let res = client
            .post(&api_body.url)
            .headers(headers_all)
            .json(&req_param)
            .send()
            .await?;

        let status = res.status();
        let text = res.text().await?;
        match status {
            StatusCode::FORBIDDEN => {
                log::error!("交易错误:{:?}", text);
                bail!("交易错误，请检查 订单号是否重复，商户是否有权限")
            }
            StatusCode::INTERNAL_SERVER_ERROR => {
                log::error!("系统错误:{:?}", text);
                bail!("系统错误")
            }

            StatusCode::UNAUTHORIZED => {
                log::error!("签名错误:{:?}", text);
                bail!("签名错误	")
            }

            e => {
                if e != 200 {
                    log::error!("签名错误:{:?}", e);
                }
            }
        }

        debug!("pre_data:{:#?}", text);
        let pre_data: PaySuccessRes = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                let v: Value = serde_json::from_str(&text)?;
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

        let content = params.appid
            + "\n"
            + now_time.to_string().as_str()
            + "\n"
            + ran_str.as_str()
            + "\n"
            + pack.as_str()
            + "\n";

        // 获取签名
        let pay_sign = self.sign(&content, &self.private_key)?;

        log::debug!("pay_sign:{}", pay_sign);

        let wx_data = WxData {
            sign_type: "RSA".into(),
            pay_sign: pay_sign,
            prepay_id: pre_data.prepay_id,
            nonce_str: ran_str,
            timestamp: now_time.to_string(),
        };

        Ok(wx_data)
    }

    pub async fn wx_pay(
        &self,
        appid: &str,
        pay_type: PayType,
        description: &str,
        out_trade_no: &str,
        total: u32,
        openid: Option<String>,
    ) -> Result<WxData, anyhow::Error> {
        let params = PayParams {
            appid: appid.to_string(),
            pay_type,
            description: description.to_string(),
            out_trade_no: out_trade_no.to_string(),
            amount: Amount { total },
            payer: openid.map(|v| Payer { openid: v }),
        };
        log::debug!("params:{:#?}", params);
        let wx_data = self.pay(params).await?;
        Ok(wx_data)
    }

    /// 微信支付订单号查询
    /// https://api.mch.weixin.qq.com/v3/pay/transactions/id/{transaction_id}
    pub async fn transactions_out_trade_no(
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
        let client = reqwest::Client::new();

        let headers_all = self.get_headers(&api_body, "")?;
        let res = client
            .get(api_body.url.clone())
            .headers(headers_all)
            .send()
            .await?;

        let status = res.status();
        let text = res.text().await?;
        match status {
            StatusCode::NOT_FOUND => {
                log::error!("订单不存在:{:?}", text);
                bail!("订单不存在")
            }
            StatusCode::BAD_REQUEST => {
                log::error!("签名错误：{:?}", text);
                bail!("订单已关闭")
            }
            StatusCode::UNAUTHORIZED => {
                log::error!("签名错误：{:?}", text);
                bail!("签名错误")
            }
            StatusCode::FORBIDDEN => {
                log::error!("交易错误:{:?}", text);
                bail!("交易错误")
            }
            StatusCode::TOO_MANY_REQUESTS => {
                log::error!("频率超限:{:?}", text);
                bail!("频率超限")
            }
            StatusCode::INTERNAL_SERVER_ERROR => {
                log::error!("订单号非法:{:?}", text);
                bail!("订单号非法 或 系统错误 或 银行系统异常")
            }
            _ => {}
        };

        let order_res: WxOrderRes = serde_json::from_str(&text)?;
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

    #[tokio::test]
    async fn test_jsapi() {
        
        let key = fs::read_to_string("./apiclient_key.pem").unwrap();
        let pay = WxPay::new(
            "1559838011",
            &key,
            "3CD22EDD308C27AB6A52FEB55A424AD4BB98254B",
            "3A252DB28DA635467AD80365E87DB041",
            "https://dot2.com/notify",
        );

        let out_trade_no = super::rand_string(32);

        let params = super::PayParams {
            pay_type: crate::wxpay::PayType::JsApi,
            description: "xxx".to_string(),
            out_trade_no: out_trade_no.clone(),
            amount: super::Amount { total: 1 },
            payer: Some(Payer {
                openid: "ojH2_6pbj0fvS4PA3pde9zCbrpKU".to_string(),
            }),
            appid: "wxd9b8baefff3dd571".to_string(),
        };
        let res = pay.pay(params).await;
        debug!("res:{:#?}", res);

        // // app
        // let params = super::PayParams {
        //     appid: "wx9b0ca8695776f224".to_string(),
        //     pay_type: crate::wx_pay::PayType::App,
        //     description: "xxx".to_string(),
        //     out_trade_no: "88888888dd5585811".to_string(),
        //     amount: super::Amount { total: 1 },
        //     payer: None,
        // };

        // let res = pay.pay(params).await;
        // debug!("res:{:#?}", res);

        // rand str
        
        let res = pay.transactions_out_trade_no(&out_trade_no).await;
        debug!("res:{:#?}", res);
    }
}
