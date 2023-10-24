# 微信支付api [参考文档地址](https://pay.weixin.qq.com/docs/partner/products/partner-jsapi-payment/introduction.html)

> 支持v2和v3接口

# 使用

> V3接口使用
```javascript
import wxpay from 'wxpay'
// 创建V3实例
const v3 = wxpay.WXPayV3.create({
  mchid: '商户id',//可以是服务商的商户id，或者直连商户的商户id
  apiV3Secret: 'V3的秘钥',// 提供V3的秘钥
  serialNo: '证书序列号',// V3加密需要使用证书序列号
  /** 生成的证书目录下的apiclient_key.pem，读取utf-8格式fs.readFileSync('apiclient_keyt.pem', 'utf8')
   * 也可以直接提取提供文件内容字符串，或文件绝对路径
   */
  privateKey: '证书的私钥',
  /** 生成的证书目录下的apiclient_cert.pem，读取utf-8格式fs.readFileSync('apiclient_cert.pem', 'utf8')
   * 也可以直接提取提供文件内容字符串，或文件绝对路径
   */
  publicKey: '证书的公钥',
})
// request方法直接发起请求，已经封装好加密信息
// 如创建商家券https://pay.weixin.qq.com/docs/partner/apis/merchant-exclusive-coupon/busi-favor/create-busifavor-stock.html
v3.request({
  url: 'https://api.mch.weixin.qq.com/v3/marketing/busifavor/stocks',
  method: 'POST',
  data: {
    "stock_name": "8月1日活动券",
    "belong_merchant": "子商户或直连商户id",
    "comment": "活动使用",
    "goods_name": "企鹅优惠券",
    "stock_type": "NORMAL",
    "coupon_use_rule": {
      "coupon_available_time": {
        "available_begin_time": "2023-10-01T13:29:35+08:00",
        "available_end_time": "2023-10-25T13:29:35+08:00",
      },
      "fixed_normal_coupon": {
        "discount_amount": 5,
        "transaction_minimum": 100
      },
      "discount_coupon": {
        "discount_percent": 88,
        "transaction_minimum": 100
      },
      "exchange_coupon": {
        "exchange_price": 100,
        "transaction_minimum": 100
      },
      "use_method": "MINI_PROGRAMS",
      "mini_programs_appid": "miniappid",
      "mini_programs_path": "/path/index/index"
    },
    "stock_send_rule": {
      "max_amount": 100000,
      "max_coupons": 100,
      "max_coupons_per_user": 5,
      "max_amount_by_day": 1000,
      "max_coupons_by_day": 100,
      "natural_person_limit": false,
      "prevent_api_abuse": false,
      "transferable": false,
      "shareable": false
    },
    "out_request_no": "请求单号，自定义",
    "custom_entrance": {
      "mini_programs_info": {
        "mini_programs_appid": "miniappid",
        "mini_programs_path": "/path/index/index",
        "entrance_words": "欢迎选购",
        "guiding_words": "获取更多优惠"
      },
      "code_display_mode": "QRCODE"
    },
    "display_pattern_info": {
      "description": "仅限测试门店可用",
      "merchant_name": "微信支付",
      "background_color": "#63B359",
    },
    "coupon_code_mode": "WECHATPAY_MODE",
    "notify_config": {
      "notify_appid": "appid"
    },
    "subsidy": false
  }
})
```
**V3的请求需要特殊注意的地方：**文件上传，因为上传的文件内容不参与签名计算，所以跟其他的接口特殊区分了，如果要上传文件直接调用`uploadMedia`函数
> 上传文件跟其他请求的唯一差别，正常请求参数body参与签名计算，文件上传仅meta参数参与签名计算
```javascript
// 因为不同的功能模块上传文件的接口不一样，因此这里提供自行填写
// base64文件格式上传
const media = await v3.uploadMedia('https://api.mch.weixin.qq.com/v3/merchant/media/upload','base64', fs.readFileSync('./0.png', 'base64'), '0.png')
console.log('v3.base64media', media.data)
// binary格式文件上传
const bmedia = await v3.uploadMedia('https://api.mch.weixin.qq.com/v3/merchant/media/upload','binary', fs.readFileSync('./0.png'), '0.png')
console.log('v3.bmedia', bmedia.data)
// 直接通过url上传
const umedia = await v3.uploadMedia('https://api.mch.weixin.qq.com/v3/merchant/media/upload','url', 'xxx/0.png', '0.png')
console.log('v3.umedia', umedia.data)
// 文件流式上传
const smedia = await v3.uploadMedia('https://api.mch.weixin.qq.com/v3/merchant/media/upload','stream', fs.createReadStream('./0.png'), '0.png')
console.log('v3.smedia', smedia.data)
```

> V2接口使用，目前官方已基本只提供V3接口，部分地方还需要V2（参考文档：https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=11_1）


```javascript
import wxpay from 'wxpay'
const v2 = wxpay.WXPayV2.create({
  mchid: '商户id',
  apiV2Secret: 'v2秘钥',
  // 需要读取为utf8格式文件内容fs.readFileSync('apiclient_cert.p12', 'utf8')
  // 也可以提供绝对文件路径
  p12: 'p12证书',
})

const params = {
  stock_id0: 'stock_id0',,
  out_request_no0: '1697028357333',
  send_coupon_merchant: '子商户号',
}
// 公众号领取商家券，需要使用V2的签名
const sign2 = v2.signHMACSHA256(params)
// 用V2接口发起请求
v2.request(...)
```