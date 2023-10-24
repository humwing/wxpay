import * as util from "./util.js";
import axios, { type AxiosRequestConfig } from "axios";
import fs from "fs";
import path from "path";
import moment from "moment";
import crypto from "crypto";
export type WXPayOptions = {
  mchid: string;
  apiV2Secret: string;
  p12: Buffer | string;
};
export default class WXPayV2 {
  options: WXPayOptions;
  /**
   *
   * @param {WXPayOptions} options
   */
  constructor(options: WXPayOptions) {
    if (options.mchid == null || options.mchid == "") {
      throw new Error("商户号不存在！");
    } else if (options.apiV2Secret == null || options.apiV2Secret == "") {
      throw new Error("密匙不存在！");
    } else if (options.p12 == null) {
      throw new Error("证书不存在！");
    }
    if (typeof options.p12 === "string" && path.isAbsolute(options.p12)) {
      options.p12 = fs.readFileSync(options.p12);
    }
    this.options = options;
  }
  /**
   * 创建一个实例
   * @param {WXPayOptions} options
   */
  public static create(options: WXPayOptions) {
    return new WXPayV2(options);
  }
  /**
   * 校验微信支付回调通知结果
   */
  validWechatpaySignature(result: { [key: string]: any }) {
    let currentSign = this.sign(result);
    let resultSign = result.sign;
    return currentSign === resultSign;
  }
  /**
   * 生成M5签名
   * @param param 签名数据
   * @returns 签名
   */
  sign(param: { [key: string]: any }) {
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
    return crypto.createHash('md5').update(querystring + "&key=" + this.options.apiV2Secret).digest('hex').toUpperCase();
  }
  // 16位就是取中间16位
  sign16(param: { [key: string]: any }) {
    const str = this.sign(param)
    return str.substring(8, 24);
  }
  /**
   * 生成HMAC-SHA256签名
   * @param param
   * @returns
   */
  signHMACSHA256(param: { [key: string]: any }) {
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
      const hash = crypto.createHmac('sha256', this.options.apiV2Secret).update(querystring + "&key=" + this.options.apiV2Secret).digest('hex');
      console.log(hash);
    return hash.toUpperCase();
  }
  /**
   * 把json转成xml数据
   * @param json json数据
   * @returns xml数据
   */
  buildXML(json:Object) {
    return util.buildXML(json);
  }
  buildMessage(messages: string[]) {
    // 因为最后一个字符也需要加上换行，join最后不会加进去，所以这里补充一个元素
    return messages.join("&");
  }
  /**
   * 获取小程序支付信息
   * @param appId 小程序appid
   * @param prepayid 统一下单返回的预支付prepayid
   * @returns 返回小程序wx.requestPayment的参数
   */
  getMiniPayInfo(appId: string, prepayid: string,signType:'MD5'|'HMAC-SHA256'='MD5') {
    let nonceStr = util.generateNonceString();
    let timeStamp = String(moment().unix());
    let message = {
      appId,
      nonceStr,
      timeStamp,
      signType,
      package: `prepay_id=${prepayid}`,
    };
    let paySign = '';
    if(signType === 'HMAC-SHA256'){
      paySign = this.signHMACSHA256(message);
    }else{
      paySign = this.sign(message);
    }
    return {
      ...message,
      paySign,
    };
  }
  /**
   * 发起微信支付v2请求
   * @param url 请求的url地址
   * @param params 请求参数，传json数据，会将json转成xml发送出去
   * @param needP12 是否需要正式，true的话会自动携带证书
   * @param options 发起http请求的其他参数配置，可以参考axios的配置，注意配置了url、method、data、httpsAgent不会生效
   * @returns 请求返回的结果，会将xml解析成json
   */
  async request(
    url: string,
    params: { [key: string]: any },
    needP12?: boolean,
    options?: AxiosRequestConfig,
  ) {
    // 如果没有nonce_str的话，自动生成一个
    params.nonce_str = params.nonce_str || util.generateNonceString();
    // 固定为MD5
    params.sign_type = "MD5";
    // 生成签名
    let sign = this.sign(params);
    // 构建xmlbody
    let body = this.buildXML(Object.assign({}, params, { sign }));
    let httpsAgent = undefined;
    if (needP12) {
      // 需要证书的时候，配置这个证书
      httpsAgent = {
        pfx: this.options.p12,
        passphrase: this.options.mchid,
      };
    }
    let { data } = await axios.request({
      ...options,
      url: url,
      method: "post",
      data: body,
      httpsAgent,
    });
    return new Promise((resolve, reject) => {
      util.parseXML(data, (err: any, data: any) => {
        if (err) {
          reject(err);
        } else {
          resolve(data);
        }
      });
    });
  }
}
