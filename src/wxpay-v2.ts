import * as util from "./util.js";
import axios, { type AxiosRequestConfig } from "axios";
import fs from "fs";
import path from "path";
import moment from "moment";
import crypto from "crypto";
export type WXPayOptions = {
  /** 商户号 */
  mchid: string;
  /** V2秘钥 */
  apiV2Secret: string;
  /** 商户p12证书 */
  p12: Buffer | string;
};
export default class WXPayV2 {
  private options: WXPayOptions;
  /**
   * 构造函数
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
  /**
   * 生成16位的MD5签名，16位就是取中间16位
   * @param param 签名参数
   * @returns 返回16位的签名
   */
  sign16(param: { [key: string]: any }) {
    const str = this.sign(param)
    return str.substring(8, 24);
  }
  /**
   * 生成HMAC-SHA256签名
   * @param param 签名参数
   * @returns 返回签名值
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
    return hash.toUpperCase();
  }
  /**
  * 微信支付H5卡券领取方法
  *
  * @param {string} stock_id - 微信支付商家券批次.
  * @param {string} open_id - 需要发放的用户openid，此openid需要是与商户号关联的公众号openid或者小程序的openid.
  * @param {string} out_request_no - 发放券码的请求流水号
  * @param {string} send_coupon_merchant - 微信支付服务商id.
  * @return {string} 返回领取链接
  */
  getH5CouponUrl(stock_id:string, open_id: string, out_request_no: string, send_coupon_merchant?:string){
    // H5签名，使用V2
    const params = {
      stock_id,
      out_request_no,
      /* 默认商户写自己，减少冗余参数传递 */
      send_coupon_merchant: send_coupon_merchant ?? this.options.mchid,
      open_id
    }
    const sign = this.signHMACSHA256(params)
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
  getWXPayCouponApiCouponInfo(
    stockList: {stock_id: string, out_request_no: string, coupon_code?: string,customize_send_time?:string}[],
    send_coupon_merchant?:string
  ){
    // 签名形式：out_request_no0=abc123&out_request_no1=123abc&send_coupon_merchant=10016226&stock_id0=1234567&stock_id1=2345678&key=xxxxx
    // 单独参与：send_coupon_merchant，相当于只能发一个商户的，不能同时发2个商户的
    const signParams = stockList.reduce((pval, item, index)=>{
      // 每项改成out_request_no0=abc123&out_request_no1=123abc这样的形式
      const itemVal = Object.keys(item).reduce((val, key)=>{
        val[`${key}${index}`] = item[key];
        return val;
      }, {})
      // 合并到一个大的对象里面
      return {
        ...pval,
        ...itemVal
      };
    }, {})
    // 再加上商户信息，默认使用当前商户，减少冗余参数传递
    signParams['send_coupon_merchant'] = send_coupon_merchant ?? this.options.mchid;
    // 生成签名
    const sign = this.signHMACSHA256(signParams)
    // 组装wx.addCard参数，此参数同时支持给到微信小程序插件、微信小程序api、微信公众号api的形式
    // 微信小程序插件
    const miniPluginParams = {
      // send_coupon_params这里还是直接传：stock_id、out_request_no，不需要带商户id
      send_coupon_params: stockList,
      send_coupon_merchant,
      sign
    }
    const miniApiParams = {
      cardList: stockList.map((item, index)=>{
        // 只需要在第一个里面传入商户id和签名
        if(index === 0){
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
