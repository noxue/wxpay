use anyhow::bail;
use chrono::Utc;
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

struct WxPay<'a> {
    pub appid: &'a str,
    pub mchid: &'a str,
    pub private_key: &'a str,
    pub serial_no: &'a str,
    pub apiv3_private_key: &'a str,
    pub notify_url: &'a str,
    pub certificates: Option<&'a str>,
}

#[derive(Serialize, Debug)]
pub struct WxData {
    pub sign_type: String,
    pub pay_sign: String,
    pub package: String,
    pub nonce_str: String,
    pub time_stamp: String,
}

#[derive(Serialize, Deserialize)]
pub struct Amount {
    pub total: u32,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Payer {
    pub openid: String,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub enum PayType {
    App,
    Mini,
}
#[derive(Serialize, Deserialize)]
pub struct PayParams {
    pub pay_type: PayType,
    pub description: String,
    pub out_trade_no: String,
    pub amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<Payer>,
}

#[derive(Clone, Copy)]
struct ApiBody<'a> {
    url: &'a str,
    method: Method,
    pathname: &'a str,
}
#[derive(Clone, Copy)]
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

impl<'a> WxPay<'a> {
    pub fn new(
        appid: &'a str,
        mchid: &'a str,
        private_key: &'a str,
        serial_no: &'a str,
        apiv3_private_key: &'a str,
        notify_url: &'a str,
        certificates: Option<&'a str>,
    ) -> Self {
        WxPay {
            appid,
            mchid,
            private_key,
            serial_no,
            apiv3_private_key,
            notify_url,
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
        api_body: ApiBody,
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

    /// js 微信支付
    pub fn pay(&self, params: PayParams) -> Result<WxData, anyhow::Error> {
        debug!("aaaj jsapi {}", &self.appid);

        if params.pay_type == PayType::Mini && params.payer.is_none() {
            bail!("微信小程序支付必须提供payer.openid");
        }
        // debug!("aaaj jsapi {:#?}", params.payer.openid);

        #[derive(Serialize, Deserialize)]
        struct RequestParam<'a> {
            description: String,
            out_trade_no: String,
            amount: Amount,
            #[serde(skip_serializing_if = "Option::is_none")]
            payer: Option<Payer>,
            appid: &'a str,
            mchid: &'a str,
            notify_url: &'a str,
        }

        let req_param = RequestParam {
            description: params.description,
            out_trade_no: params.out_trade_no,
            amount: params.amount,
            payer: params.payer,
            appid: &self.appid,
            mchid: &self.mchid,
            notify_url: &self.notify_url,
        };

        let req_param_str = serde_json::to_string(&req_param).unwrap();

        debug!("req_param_str:{}", req_param_str);
        let api_body = match params.pay_type {
            PayType::App => ApiBody {
                url: "https://api.mch.weixin.qq.com/v3/pay/transactions/app",
                method: Method::POST,
                pathname: "/v3/pay/transactions/app",
            },
            PayType::Mini => ApiBody {
                url: "https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi",
                method: Method::POST,
                pathname: "/v3/pay/transactions/jsapi",
            },
        };

        let headers_all = self.get_headers(api_body, &req_param_str)?;

        #[derive(Serialize, Deserialize, Debug)]
        struct PaySuccessRes {
            prepay_id: String,
        }
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(api_body.url.clone())
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
            package: pack,
            nonce_str: ran_str,
            time_stamp: now_time.to_string(),
        };

        Ok(wx_data)
    }

    /// 微信支付订单号查询
    /// https://api.mch.weixin.qq.com/v3/pay/transactions/id/{transaction_id}
    pub fn transactions_out_trade_no(
        &self,
        out_trade_no: &str,
    ) -> Result<WxOrderRes, anyhow::Error> {
        let api_body = ApiBody {
            url: &format!(
                "https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/{}?mchid={}",
                out_trade_no, self.mchid
            ),
            method: Method::GET,
            pathname: &format!(
                "/v3/pay/transactions/out-trade-no/{}?mchid={}",
                out_trade_no, self.mchid
            ),
        };
        let client = reqwest::blocking::Client::new();

        let headers_all = self.get_headers(api_body, "")?;
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
