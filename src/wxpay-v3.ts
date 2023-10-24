import * as utils from "./util.js";
import axios, { type AxiosInstance, type AxiosRequestConfig } from "axios";
import { URL } from "url";
import crypto from "crypto";
import moment from "moment";
import path from "path";
import FormData from "form-data";
import fs from "fs";
import RSA from "./rsa.js";
type Options = {
  mchid: string;
  serialNo?: string;
  privateKey?: string | crypto.KeyObject;
  privateKeyStr?: string;
  publicKey?: string | crypto.KeyObject;
  publicKeyStr?: string;
  apiV3Secret?: string;
};

type WXPayPlatformCert = {
  /** @property 证书编号，在支付平台申请正式之后可以得到，或者读取cert_pem里面的serial_no也可以得到 */
  "serial_no": string;
  /** @property 生效时间，从什么时候开始生效*/
  "effective_time": Date;
  /** @property 过期时间，从什么时候开始过期*/
  "expire_time ": Date;
  /** @property 解密证书信息*/
  "decrypt_certificate"?: any;
  /** @property 加密证书信息*/
  "encrypt_certificate": {
    /** @property 加密算法*/
    algorithm: string;
    /** @property 随机字符串*/
    nonce: string;
    /** @property 关联数据*/
    associated_data: string;
    /** @property 密文，这里解密可以得到证书的明文*/
    ciphertext: string;
  };
};

function X509Certificate(publicEncrypt:any) {
  if(crypto.X509Certificate){
    let cert = new crypto.X509Certificate(publicEncrypt);
    return cert.publicKey;
  }else{
    return crypto.createPublicKey(publicEncrypt);
  }
}
export default class WXPayV3 {
  options: Options;
  axios: AxiosInstance;
   /**
   * 初始化
   * @constructs WXPayV3
   * @param {Omit<Options, 'publicKeyStr'|'privateKeyStr'>} options
   * @returns
   */
  constructor(options: Omit<Options, 'publicKeyStr'|'privateKeyStr'>) {
    const _options: Options = options;
    if (
      options.privateKey instanceof crypto.KeyObject &&
      options.privateKey.type !== "private"
    ) {
      throw new Error("私钥错误，请提供正确的私钥！");
    }
    if (
      options.publicKey instanceof crypto.KeyObject &&
      options.publicKey.type !== "public"
    ) {
      throw new Error("公钥错误，请提供正确的公钥！");
    }
    if (
      typeof options.privateKey === "string" &&
      /-----BEGIN PRIVATE KEY-----/.test(options.privateKey)
    ) {
      _options.privateKeyStr = options.privateKey;
      _options.privateKey = crypto.createPrivateKey(options.privateKey);
    } else if (
      typeof options.privateKey === "string" &&
      path.isAbsolute(options.privateKey)
    ) {
      let privateKeyStr = fs.readFileSync(options.privateKey, "utf-8");
      _options.privateKey = crypto.createPrivateKey(privateKeyStr);
      _options.privateKeyStr = privateKeyStr;
    }
    if (
      typeof options.publicKey === "string" &&
      /-----BEGIN CERTIFICATE-----/.test(options.publicKey)
    ) {
      let publicKey = X509Certificate(options.publicKey);
      _options.publicKeyStr = options.publicKey;
      _options.publicKey = publicKey;
    } else if (
      typeof options.publicKey === "string" &&
      path.isAbsolute(options.publicKey)
    ) {
      let publicKeyStr = fs.readFileSync(options.publicKey, "utf-8");
      let publicKey = X509Certificate(options.publicKey);
      _options.publicKeyStr = publicKeyStr;
      _options.publicKey = publicKey;
    }
    if (options.apiV3Secret?.length !== 32) {
      throw new Error("api秘钥错误！");
    }
    this.options = _options;
    let _axios = axios.create();
    _axios.interceptors.request.use((config) => {
      let requestUrl = utils.buildURL(
        config.url as string,
        config.params,
        config.paramsSerializer,
      );
      let requestURL = new URL(requestUrl);

      let token = this.getToken(
        config.method as string,
        requestURL.pathname + requestURL.search,
        config.data,
      );
      config.headers = config.headers || {} as any;
      config.headers.Authorization = `WECHATPAY2-SHA256-RSA2048 ${token}`;
      return config;
    });
    this.axios = _axios;
  }
  /**
   * 创建实例
   * @param {Omit<Options, 'publicKeyStr'|'privateKeyStr'>} options 除publicKeyStr和privateKeyStr字段
   * @returns
   */
  public static create(options: Omit<Options, 'publicKeyStr'|'privateKeyStr'>) {
    return new WXPayV3(options);
  }
  /**
   * 获取微信支付apiv3的token
   * @param method 请求方法
   * @param url 请求url
   * @param body 请求参数
   * @returns
   */
  getToken(method: string, url: string, body?: { [key: string]: any }) {
    let nonceStr = utils.generateNonceString();
    let timestamp = String(moment().unix());
    let message = this.buildMessage([
      method,
      url,
      timestamp,
      nonceStr,
      body ? JSON.stringify(body) : "",
    ]);
    console.log("getToken", message);
    let signature = this.sign(message);
    console.log("getToken", signature);
    return `mchid="${this.options.mchid}",nonce_str="${nonceStr}",timestamp="${timestamp}",serial_no="${this.options.serialNo}",signature="${signature}"`;
  }
  /**
   * 生成签名
   * @param message 签名信息
   * @returns 签名结果
   */
  sign(message: string) {
    const sign = crypto.createSign("RSA-SHA256");
    sign.update(message);
    const signature = sign.sign(this.options.privateKey as string, "base64");
    return signature;
  }
  /**
   * 加密数据，参考https://pay.weixin.qq.com/wiki/doc/apiv3/wechatpay/wechatpay4_3.shtml
   * @param text 加密字符串
   * @param additional_authenticated_data 鉴权数据
   * @param iv 初始向量，一般是取一个nonce字符串
   * @returns
   */
  encryptData(text: string, additional_authenticated_data: string, iv: string) {
    let cipher = crypto.createCipheriv(
      "aes-256-gcm",
      this.options.apiV3Secret as string,
      iv,
    );
    cipher.setAAD(Buffer.from(additional_authenticated_data, "utf-8"));
    let ciphertext = cipher.update(Buffer.from(text, "utf-8"));
    let encrypted = Buffer.concat([
      ciphertext,
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    return {
      ciphertext: encrypted.toString("base64"),
      associated_data: additional_authenticated_data,
      nonce: iv,
    };
  }
  async encryptPublic(text: string, serial_no?: string) {
    let cert = await this.getPlatformCert(serial_no, true);
    return RSA.encrypt(text, cert[0]?.decrypt_certificate);
  }
  async decryptPublic(ciphertext: string) {
    return RSA.decrypt(ciphertext, this.options.privateKeyStr as string);
  }
  private getHash(stream: fs.ReadStream) {
    return new Promise((resolve, reject) => {
      let hash = crypto.createHash("sha256");
      stream.pipe(hash);
      hash.on("finish", () => {
        const data = hash.read();
        if (data) {
          resolve(data.toString("hex"));
        }
      });
      hash.on("error", (e) => {
        reject(e);
      });
    });
  }
  async uploadMediaByBase64(
    base64: string,
    filename: string,
    type?: "image" | "video",
  ) {
    let form = new FormData();
    let data = fs.createReadStream(Buffer.from(base64, "base64"));
    form.append("file", data);
    // 读取文件的hash值
    let sha256 = await this.getHash(data);
    let meta = {
      filename: filename,
      sha256: sha256,
    };
    form.append("meta", JSON.stringify(meta));
    let params: any = {
      url: `https://api.mch.weixin.qq.com/v3/merchant/media/${
        type === "video" ? "video_upload" : "upload"
      }`,
      method: "POST",
      data: form,
      headers: form.getHeaders(),
    };
    let requestUrl = utils.buildURL(
      params.url,
      params.params,
      params.paramsSerializer,
    );
    let requestURL = new URL(requestUrl);
    // 构建请求的token
    let token = this.getToken(
      params.method,
      requestURL.pathname + requestURL.search,
      meta,
    );
    params.headers = params.headers || {};
    params.headers.Authorization = `WECHATPAY2-SHA256-RSA2048 ${token}`;
    console.log(params.headers.Authorization);
    return axios.request(params);
  }
  async uploadMediaByStream(
    data: fs.ReadStream,
    filename: string,
    type?: "image" | "video",
  ) {
    let form = new FormData();
    form.append("file", data);
    // 读取文件的hash值
    let sha256 = await this.getHash(data);
    let meta = {
      filename: filename,
      sha256: sha256,
    };
    form.append("meta", JSON.stringify(meta));
    let params: any = {
      url: `https://api.mch.weixin.qq.com/v3/merchant/media/${
        type === "video" ? "video_upload" : "upload"
      }`,
      method: "POST",
      data: form,
      headers: form.getHeaders(),
    };
    let requestUrl = utils.buildURL(
      params.url,
      params.params,
      params.paramsSerializer,
    );
    let requestURL = new URL(requestUrl);
    // 构建请求的token
    let token = this.getToken(
      params.method,
      requestURL.pathname + requestURL.search,
      meta,
    );
    params.headers = params.headers || {};
    params.headers.Authorization = `WECHATPAY2-SHA256-RSA2048 ${token}`;
    console.log(params.headers.Authorization);
    return axios.request(params);
  }
  async uploadMediaByUrl(fileUrl: string, type?: "image" | "video") {
    let form = new FormData();
    // 下载文件
    let { data } = await axios.get(fileUrl, {
      responseType: "stream",
    });
    let lastFileIndex = fileUrl.lastIndexOf("/");
    // 获取文件名
    let urlName = fileUrl.substr(lastFileIndex + 1);
    form.append("file", data);
    // 读取文件的hash值
    let sha256 = await this.getHash(data);
    let meta = {
      filename: urlName,
      sha256: sha256,
    };
    form.append("meta", JSON.stringify(meta));
    let params: any = {
      url: `https://api.mch.weixin.qq.com/v3/merchant/media/${
        type === "video" ? "video_upload" : "upload"
      }`,
      method: "POST",
      data: form,
      headers: form.getHeaders(),
    };
    let requestUrl = utils.buildURL(
      params.url,
      params.params,
      params.paramsSerializer,
    );
    let requestURL = new URL(requestUrl);
    // 构建请求的token
    let token = this.getToken(
      params.method,
      requestURL.pathname + requestURL.search,
      meta,
    );
    params.headers = params.headers || {};
    params.headers.Authorization = `WECHATPAY2-SHA256-RSA2048 ${token}`;
    console.log(params.headers.Authorization);
    return axios.request(params);
  }
  async uploadImageByUrl(fileUrl: string) {
    let form = new FormData();
    let { data } = await axios.get(fileUrl, {
      responseType: "stream",
    });
    let lastFileIndex = fileUrl.lastIndexOf("/");
    let urlName = fileUrl.substr(lastFileIndex + 1);
    form.append("file", data);
    let sha256 = await this.getHash(data);
    let meta = {
      filename: urlName,
      sha256: sha256,
    };
    form.append("meta", JSON.stringify(meta));
    let params: any = {
      url: "https://api.mch.weixin.qq.com/v3/merchant/media/upload",
      method: "POST",
      data: form,
      headers: form.getHeaders(),
    };
    let requestUrl = utils.buildURL(
      params.url,
      params.params,
      params.paramsSerializer,
    );
    let requestURL = new URL(requestUrl);
    let token = this.getToken(
      params.method,
      requestURL.pathname + requestURL.search,
      meta,
    );
    params.headers = params.headers || {};
    params.headers.Authorization = `WECHATPAY2-SHA256-RSA2048 ${token}`;
    console.log(params.headers.Authorization);
    return axios.request(params);
  }
  async uploadVideoByUrl(fileUrl: string) {
    let form = new FormData();
    let { data } = await axios.get(fileUrl, {
      responseType: "stream",
    });
    let lastFileIndex = fileUrl.lastIndexOf("/");
    let urlName = fileUrl.substr(lastFileIndex + 1);
    form.append("file", data);
    let sha256 = await this.getHash(data);
    let meta = {
      filename: urlName,
      sha256: sha256,
    };
    form.append("meta", JSON.stringify(meta));
    let params: any = {
      url: "https://api.mch.weixin.qq.com/v3/merchant/media/video_upload",
      method: "POST",
      data: form,
      headers: form.getHeaders(),
    };
    let requestUrl = utils.buildURL(
      params.url,
      params.params,
      params.paramsSerializer,
    );
    let requestURL = new URL(requestUrl);

    let token = this.getToken(
      params.method,
      requestURL.pathname + requestURL.search,
      meta,
    );
    params.headers = params.headers || {};
    params.headers.Authorization = `WECHATPAY2-SHA256-RSA2048 ${token}`;
    console.log(params.headers.Authorization);
    return axios.request(params);
  }
  /**
   * 解密证书
   * @param ciphertext  Base64编码后的开启/停用结果数据密文
   * @param associated_data 附加数据
   * @param nonce 加密使用的随机串
   * @param key  APIv3密钥
   */
  public decipher(
    ciphertext: string,
    associated_data: string,
    nonce: string,
    key?: string,
  ) {
    key = key ?? this.options.apiV3Secret;
    if (!key) throw new Error("缺少key");

    const _ciphertext = Buffer.from(ciphertext, "base64");

    // 解密 ciphertext字符  AEAD_AES_256_GCM算法
    const authTag: any = _ciphertext.slice(_ciphertext.length - 16);
    const data = _ciphertext.slice(0, _ciphertext.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(authTag);
    decipher.setAAD(Buffer.from(associated_data));
    const decoded = decipher.update(data, undefined, "utf8");
    decipher.final();
    return decoded;
  }

  async decryptData(
    ciphertext: string,
    associated_data: string,
    nonce: string,
  ): Promise<{ [key: string]: any }> {
    let res = this.decipher(ciphertext, associated_data, nonce);
    try {
      res = JSON.parse(res);
    } catch (error) {
      console.log("[decrypt data]", "数据格式不是json");
    }
    return res as any;
  }
  /**
   *
   * @param wechatpayTimestamp 微信支付返回的时间戳
   * @param wechatpayNonce  微信支付返回的随机串
   * @param wechatpaySignature  微信支付返回的签名串
   * @param wechatpayData   微信支付返回的数据
   * @param wechatpayCert   微信支付的平台证书
   * @returns
   */
  public async validWechatpaySignature({
    wechatpayTimestamp,
    wechatpayNonce,
    wechatpaySignature,
    wechatpayData,
    wechatpayCert,
    wechatpaySerial,
  }: {
    wechatpayTimestamp: string;
    wechatpayNonce: string;
    wechatpaySignature: string;
    wechatpayData: any;
    wechatpayCert?: string;
    wechatpaySerial?: string;
  }) {
    if (wechatpayData && typeof wechatpayData !== "string") {
      wechatpayData = JSON.stringify(wechatpayData);
    }
    if (!wechatpayCert && wechatpaySerial) {
      let certs = await this.getPlatformCert(wechatpaySerial, true);
      wechatpayCert = certs[0]?.decrypt_certificate;
    }
    let keyObject = crypto.createPublicKey(wechatpayCert as string);
    let verify = crypto.createVerify("RSA-SHA256");
    verify.update(
      `${wechatpayTimestamp}` +
        "\n" +
        `${wechatpayNonce}` +
        "\n" +
        `${wechatpayData}` +
        "\n",
    );
    let valid = verify.verify(keyObject, wechatpaySignature, "base64");
    return valid;
  }
  async getPlatformCert(
    serial_no?: string,
    decrypt?: boolean,
  ): Promise<WXPayPlatformCert[]> {
    return await this.getWXPayPlatformCert(serial_no, decrypt);
  }
  /**
   * 获取微信支付平台证书
   * @param serial_no 指定证书编号，如果指定了则返回指定的，否则返回全部
   * @param decrypt 是否解密证书内容，默认不解密
   * @returns 返回证书列表
   */
  private async getWXPayPlatformCert(serial_no?: string, decrypt?: boolean) {
    let {
      data,
    }: {
      data: {
        data: WXPayPlatformCert[];
      };
    } = await this.request({
      method: "GET",
      url: "https://api.mch.weixin.qq.com/v3/certificates",
      headers: {
        "Accept": "application/json",
        "User-Agent": "nodejs",
      },
    });
    if (decrypt) {
      data.data?.map((item: WXPayPlatformCert) => {
        item.encrypt_certificate = this.decipher(
          item.encrypt_certificate.ciphertext,
          item.encrypt_certificate.associated_data,
          item.encrypt_certificate.nonce,
        ) as any;
        return item;
      });
    }
    if (serial_no) {
      return data.data.filter((item) => {
        return item.serial_no === serial_no;
      });
    }
    return data.data;
  }
  /**
   * 构造签名字符串
   * @param messages 签名信息
   * @returns
   */
  buildMessage(messages: string[]) {
    // 因为最后一个字符也需要加上换行，join最后不会加进去，所以这里补充一个元素
    return messages.concat("").join("\n");
  }
  /**
   * 获取小程序支付信息，apiv3
   * @param appid 小程序的appid
   * @param prepayid 订单信息，来自小程序下单的返回
   * @returns
   */
  getMiniPayInfo(appid: string, prepayid: string) {
    let nonceStr = utils.generateNonceString();
    let timeStamp = String(moment().unix());
    let mpackage = "prepay_id=" + prepayid;
    let message = this.buildMessage([appid, timeStamp, nonceStr, mpackage]);
    let paySign = this.sign(message);
    return {
      timeStamp,
      nonceStr,
      package: mpackage,
      signType: "RSA",
      paySign,
    };
  }
  /**
   * 发起请求
   * @param params 请求数据
   * @returns 请求结果
   */
  request(params: AxiosRequestConfig) {
    let requestUrl = utils.buildURL(
      params.url as string,
      params.params,
      params.paramsSerializer,
    );
    let requestURL = new URL(requestUrl);

    let token = this.getToken(
      params.method ?? "GET",
      requestURL.pathname + requestURL.search,
      params.data,
    );
    params.headers = params.headers || {};
    params.headers.Authorization = `WECHATPAY2-SHA256-RSA2048 ${token}`;
    return axios.request(params);
  }
}
