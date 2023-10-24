import { Stream } from "stream";
import xml2js from "xml2js";
import { v4 } from "uuid";
import crypto from "crypto";
export const buildXML = function (json: any) {
  var builder = new xml2js.Builder();
  return builder.buildObject(json);
};

function loop(..._args: any[]) {}
export const parseXML = function (xml: string, fn?: Function) {
  var parser = new xml2js.Parser({
    trim: true,
    explicitArray: false,
    explicitRoot: false,
  });
  parser.parseString(xml, fn || loop as any);
};

export const parseRaw = function () {
  return function (
    req: Stream & { rawbody: string },
    _res: any,
    next?: Function,
  ) {
    var buffer: Uint8Array[] = [];
    req.on("data", function (trunk) {
      buffer.push(trunk);
    });
    req.on("end", function () {
      req.rawbody = Buffer.concat(buffer).toString("utf8");
      next?.();
    });
    req.on("error", function (err) {
      next?.(err);
    });
  };
};

export const pipe = function (stream: Stream, fn: (...args: any[]) => void) {
  var buffers: Uint8Array[] = [];
  stream.on("data", function (trunk) {
    buffers.push(trunk);
  });
  stream.on("end", function () {
    fn(null, Buffer.concat(buffers));
  });
  stream.once("error", fn);
};

export const mix = function (...args: any) {
  var root = args[0];
  if (args.length == 1) {
    return root;
  }
  for (var i = 1; i < args.length; i++) {
    for (var k in args[i]) {
      root[k] = args[i][k];
    }
  }
  return root;
};
export const isExpired = function (data: { expires_timestamp: number }) {
  return +data.expires_timestamp < Date.now();
};
export const isValid = function (data: { expires_timestamp: number }) {
  return !isExpired(data);
};
export const generateNonceString = function (length: number = 32) {
  var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  var maxPos = chars.length;
  var noceStr = "";
  for (var i = 0; i < length; i++) {
    noceStr += chars.charAt(Math.floor(Math.random() * maxPos));
  }
  return noceStr;
};

export function signatureTicket(jsapi_ticket: string, url: string) {
  let noncestr = v4();
  let timestamp = Date.now();
  let str = `jsapi_ticket=${jsapi_ticket}&noncestr=${noncestr}&timestamp=${timestamp}&url=${url}`;
  let signature = crypto.createHash("sha1").update(str).digest("hex");
  return {
    noncestr,
    timestamp,
    signature,
  };
}
var toString = Object.prototype.toString;

/**
 * Determine if a value is an Array
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is an Array, otherwise false
 */
export function isArray(val: any) {
  return toString.call(val) === "[object Array]";
}
/**
 * Determine if a value is an Object
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is an Object, otherwise false
 */
export function isObject(val: null) {
  return val !== null && typeof val === "object";
}
/**
 * Determine if a value is a Date
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Date, otherwise false
 */
export function isDate(val: any) {
  return toString.call(val) === "[object Date]";
}
/**
 * Iterate over an Array or an Object invoking a function for each item.
 *
 * If `obj` is an Array callback will be called passing
 * the value, index, and complete array for each item.
 *
 * If 'obj' is an Object callback will be called passing
 * the value, key, and complete object for each property.
 *
 * @param {Object|Array} obj The object to iterate
 * @param {Function} fn The callback to invoke for each item
 */
export function forEach(obj: any, fn: any) {
  // Don't bother if no value provided
  if (obj === null || typeof obj === "undefined") {
    return;
  }

  // Force an array if not already something iterable
  if (typeof obj !== "object") {
    /*eslint no-param-reassign:0*/
    obj = [obj];
  }

  if (isArray(obj)) {
    // Iterate over array values
    for (var i = 0, l = obj.length; i < l; i++) {
      fn.call(null, obj[i], i, obj);
    }
  } else {
    // Iterate over object keys
    for (var key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        fn.call(null, obj[key], key, obj);
      }
    }
  }
}
export function encode(val:string) {
  return encodeURIComponent(val)
    .replace(/%3A/gi, ":")
    .replace(/%24/g, "$")
    .replace(/%2C/gi, ",")
    .replace(/%20/g, "+")
    .replace(/%5B/gi, "[")
    .replace(/%5D/gi, "]");
}
/**
 * Build a URL by appending params to the end
 *
 * @param {string} url The base of the url (e.g., http://www.google.com)
 * @param {object} [params] The params to be appended
 * @returns {string} The formatted url
 */
export function buildURL(
  url: string,
  params: { [key: string]: any },
  paramsSerializer: any,
) {
  /*eslint no-param-reassign:0*/
  if (!params) {
    return url;
  }

  var serializedParams;
  if (paramsSerializer) {
    serializedParams = paramsSerializer(params);
  } else if (
    typeof URLSearchParams !== "undefined" &&
    params instanceof URLSearchParams
  ) {
    serializedParams = params.toString();
  } else {
    var parts: string[] = [];

    forEach(params, function serialize(val:any, key:any) {
      if (val === null || typeof val === "undefined") {
        return;
      }

      if (isArray(val)) {
        key = key + "[]";
      } else {
        val = [val];
      }

      forEach(val, function parseValue(v:any) {
        if (isDate(v)) {
          v = v.toISOString();
        } else if (isObject(v)) {
          v = JSON.stringify(v);
        }
        parts.push(encode(key) + "=" + encode(v));
      });
    });

    serializedParams = parts.join("&");
  }

  if (serializedParams) {
    var hashmarkIndex = url.indexOf("#");
    if (hashmarkIndex !== -1) {
      url = url.slice(0, hashmarkIndex);
    }

    url += (url.indexOf("?") === -1 ? "?" : "&") + serializedParams;
  }

  return url;
}