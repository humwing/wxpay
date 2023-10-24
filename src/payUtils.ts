import crypto from "crypto";
/**
 * 工具函数集合
 */
const PayUtil = {
  /**
   * 获取签名
   * @param message 需要被签名的信息
   * @param privateKey 私钥，PRIVATE KEY
   * @returns 签名信息
   */
  sign(message: string, privateKey: string) {
    const sign = crypto.createSign("RSA-SHA256");
    sign.update(message);
    const signature = sign.sign(privateKey, "base64");
    return signature;
  },
  /**
   * 加密数据
   * @param data 待加密的字符串
   * @param aad 额外的鉴权信息
   * @param iv 初始向量
   * @param secret 密钥
   * @returns 加密数据
   */
  encrypt(data: string, aad: string, iv: string, secret: string) {
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
  },
  /**
   * 解密数据
   * @param ciphertext 密文
   * @param aad 鉴权数据
   * @param iv 初始向量
   * @param secret 密钥
   * @returns 界面的数据
   */
  decipher(ciphertext: string, aad: string, iv: string, secret: string) {
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
  },
  /**
   * 构建签名的信息
   * @param messages 信息数组
   * @returns 返回构建好的字符串
   */
  buildMessage(messages: string[]) {
    // 因为最后一个字符也需要加上换行，join最后不会加进去，所以这里补充一个元素
    return messages.concat("").join("\n");
  },
};

export default PayUtil;