import crypto from "crypto";
/**
* 获取RSA-SHA256签名，返回base64格式
* @param message 需要被签名的信息
* @param privateKey 私钥，PRIVATE KEY
* @returns 签名信息
*/
export function signRSASHA256(message: string, privateKey: string) {
  const sign = crypto.createSign("RSA-SHA256");
  sign.update(message);
  const signature = sign.sign(privateKey, "base64");
  return signature;
}
/**
* 微信支付H5卡券领取方法
*
* @param {string} stock_id - 微信支付商家券批次.
* @param {string} send_coupon_merchant - 微信支付服务商id.
* @param {string} open_id - 需要发放的用户openid，此openid需要是与商户号关联的公众号openid或者小程序的openid.
* @return {string} 返回领取链接
*/
export function getH5CouponUrl(stock_id: string, send_coupon_merchant: string, open_id: string, secret: string) {
  // H5签名，使用V2
  const params = {
    stock_id,
    out_request_no: Date.now(),
    send_coupon_merchant,
    open_id
  }
  const sign = signHMACSHA256(params, secret)
  const url = `https://action.weixin.qq.com/busifavor/getcouponinfo?stock_id=${params.stock_id}&out_request_no=${params.out_request_no}&sign=${sign}&send_coupon_merchant=${params.send_coupon_merchant}&open_id=${open_id}#wechat_redirect`
  return url;
}
/**
* 微信支付卡券领取参数生成
*
* @param {Array<{stock_id: string, out_request_no: string, coupon_code?: string,customize_send_time?:string}>} stockList - 微信卡券批次信息
* @param {string|number} send_coupon_merchant 商户id，服务商请填写服务商id，直连商户填直连商户id
* @return {{miniPluginParams,miniApiParams,jssdkParams}} an object containing three parameters: miniPluginParams, miniApiParams, and jssdkParams
*/
export function getWXPayCouponApiCouponInfo(stockList, send_coupon_merchant, secret: string) {
  // 签名形式：out_request_no0=abc123&out_request_no1=123abc&send_coupon_merchant=10016226&stock_id0=1234567&stock_id1=2345678&key=xxxxx
  // 单独参与：send_coupon_merchant，相当于只能发一个商户的，不能同时发2个商户的
  const signParams = stockList.reduce((pval, item, index) => {
    // 每项改成out_request_no0=abc123&out_request_no1=123abc这样的形式
    const itemVal = Object.keys(item).reduce((val, key) => {
      val[`${key}${index}`] = item[key];
      return val;
    }, {})
    // 合并到一个大的对象里面
    return {
      ...pval,
      ...itemVal
    };
  }, {})
  // 再加上商户信息
  signParams['send_coupon_merchant'] = send_coupon_merchant;
  // 生成签名
  const sign = this.signHMACSHA256(signParams, secret)
  // 组装wx.addCard参数，此参数同时支持给到微信小程序插件、微信小程序api、微信公众号api的形式
  // 微信小程序插件
  const miniPluginParams = {
    // send_coupon_params这里还是直接传：stock_id、out_request_no，不需要带商户id
    send_coupon_params: stockList,
    send_coupon_merchant,
    sign
  }
  const miniApiParams = {
    cardList: stockList.map((item, index) => {
      // 只需要在第一个里面传入商户id和签名
      if (index === 0) {
        return {
          cardId: item.stock_id,  //对应商家券批次号
          cardExt: JSON.stringify({
            sign,
            send_coupon_merchant,
            coupon_code: item.coupon_code,
            customize_send_time: item.customize_send_time,
            out_request_no: item.out_request_no,
          })
        }
      }
      return {
        cardId: item.stock_id,  //对应商家券批次号
        cardExt: JSON.stringify({
          coupon_code: item.coupon_code,
          customize_send_time: item.customize_send_time,
          out_request_no: item.out_request_no,
        })
      };
    })
  }
  return {
    miniPluginParams,
    miniApiParams,
    jssdkParams: miniApiParams
  }
}
/**
 * 微信体系模式的Hmac sha256签名
 * @param param 任意的参数形式
 * @param secret 签名秘钥
 * @returns sha256签名
 */
export function signHMACSHA256(param: { [key: string]: any }, secret: string) {
  let querystring = Object.keys(param)
    .sort()
    .filter((key) => {
      return param[key] != null && param[key] !== "";
    })
    .filter((key) => {
      return ["sign", "key"].indexOf(key) < 0;
    })
    .map((key) => {
      return key + "=" + param[key];
    })
    .join("&");
  const hash = crypto.createHmac('sha256', secret).update(querystring + "&key=" + secret).digest('hex');
  return hash.toUpperCase();
}
/**
 * aes-256-gcm加密数据
 * @param data 待加密的字符串
 * @param aad 额外的鉴权信息
 * @param iv 初始向量
 * @param secret 密钥
 * @returns 加密数据
 */
export function encrypt(data: string, aad: string, iv: string, secret: string) {
  let cipher = crypto.createCipheriv("aes-256-gcm", secret, iv);
  cipher.setAAD(Buffer.from(aad, "utf-8"));
  let ciphertext = cipher.update(Buffer.from(data, "utf-8"));
  let encrypted = Buffer.concat([
    ciphertext,
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return {
    ciphertext: encrypted.toString("base64"),
    associated_data: aad,
    nonce: iv,
  };
}
/**
 * aes-256-gcm解密数据
 * @param ciphertext 密文
 * @param aad 鉴权数据
 * @param iv 初始向量
 * @param secret 密钥
 * @returns 界面的数据
 */
export function decipher(ciphertext: string, aad: string, iv: string, secret: string) {
  const _ciphertext = Buffer.from(ciphertext, "base64");
  // 解密 ciphertext字符  AEAD_AES_256_GCM算法
  const authTag: any = _ciphertext.slice(_ciphertext.length - 16);
  const data = _ciphertext.slice(0, _ciphertext.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", secret, iv);
  decipher.setAuthTag(authTag);
  decipher.setAAD(Buffer.from(aad));
  const decoded = decipher.update(data, undefined, "utf8");
  decipher.final();
  return decoded;
}
/**
 * 构建签名的信息
 * @param messages 信息数组
 * @returns 返回构建好的字符串
 */
export function buildMessage(messages: string[]) {
  // 因为最后一个字符也需要加上换行，join最后不会加进去，所以这里补充一个元素
  return messages.concat("").join("\n");
}
/**
 * 工具函数集合
 */
const PayUtil = {
  signRSASHA256,
  getH5CouponUrl,
  getWXPayCouponApiCouponInfo,
  signHMACSHA256,
  encrypt,
  decipher,
  buildMessage,
};

export default PayUtil;