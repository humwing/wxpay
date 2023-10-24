import {
  publicEncrypt,
  privateDecrypt,
  createSign,
  createVerify,
  constants,
  type BinaryLike,
  type KeyLike,
  type VerifyJsonWebKeyInput,
  type VerifyKeyObjectInput,
  type VerifyPublicKeyInput,
} from "crypto";

/** @constant 'sha1' */
const sha1 = "sha1";
/** @constant 'utf8' */
const utf8 = "utf8";
/** @constant 'base64' */
const base64 = "base64";
/** @constant 'sha256WithRSAEncryption' */
const sha256WithRSAEncryption = "sha256WithRSAEncryption";

/**
 * Provides some methods for the RSA `sha256WithRSAEncryption` with `RSA_PKCS1_OAEP_PADDING`.
 */

export default class Rsa {
  /**
   * Encrypts text with sha256WithRSAEncryption/RSA_PKCS1_OAEP_PADDING.
   * Recommended Node Limits Version >= 12.9.0 (`oaepHash` was available), even if it works on v10.15.0.
   *
   * @param {string} plaintext - Cleartext to encode.
   * @param {string|Buffer} publicKey - A PEM encoded public certificate.
   *
   * @returns {string} Base64-encoded ciphertext.
   */
  static encrypt(plaintext:string, publicKey:string) {
    return publicEncrypt(
      {
        oaepHash: sha1,
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
      },
      Buffer.from(plaintext, utf8),
    ).toString(base64);
  }

  /**
   * Decrypts base64 encoded string with `privateKey`.
   * Recommended Node Limits Version >= 12.9.0 (`oaepHash` was available), even if it works on v10.15.0.
   *
   * @param {string} ciphertext - Was previously encrypted string using the corresponding public certificate.
   * @param {string|Buffer} privateKey - A PEM encoded private key certificate.
   *
   * @returns {string} Utf-8 plaintext.
   */
  static decrypt(ciphertext: string, privateKey: string) {
    return privateDecrypt(
      {
        oaepHash: sha1,
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
      },
      Buffer.from(ciphertext, base64),
    ).toString(utf8);
  }

  /**
   * Creates and returns a `Sign` string that uses `sha256WithRSAEncryption`.
   *
   * @param {string|Buffer} message - Content will be `crypto.Sign`.
   * @param {string|Buffer} privateKey - A PEM encoded private key certificate.
   *
   * @returns {string} Base64-encoded signature.
   */
  static sign(message: string, privateKey: string) {
    return createSign(sha256WithRSAEncryption)
      .update(message)
      .sign(privateKey, base64);
  }

  /**
   * Verifying the `message` with given `signature` string that uses `sha256WithRSAEncryption`.
   *
   * @param {string|Buffer} message - Content will be `crypto.Verify`.
   * @param {string} signature - The base64-encoded ciphertext.
   * @param {string|Buffer} publicKey - A PEM encoded public certificate.
   *
   * @returns {boolean} True is passed, false is failed.
   */
  static verify(message: BinaryLike, signature: string, publicKey: KeyLike | VerifyKeyObjectInput | VerifyPublicKeyInput | VerifyJsonWebKeyInput) {
    return createVerify(sha256WithRSAEncryption)
      .update(message)
      .verify(publicKey, signature, base64);
  }
}
