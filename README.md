# node-cborwebtoken
[![Build Status](https://travis-ci.org/netnexus/node-cborwebtoken.svg?branch=develop)](https://travis-ci.org/netnexus/node-cborwebtoken)

An implementation of CBOR Web Tokens for node (TypeScript, JavaScript).

This was developed against [draft-ietf-ace-cbor-web-token-08](https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token-08).

# Install
```bash
$ npm install node-cborwebtoken
```

# Usage

## cwt.mac(payload, secret)

Returns the CborWebToken as a string.

Example:
```js
const tokenResponse = cwt.mac(payload, secret ).then((tokenResponse) => {
    console.log(tokenResponse);
});
```

## cwt.verify(token, secret)

Returns the payload decoded if the signature (and, optionally, expiration, audience, issuer) are valid. If not, it will throw an error.

Example:
```js
const verifyTest = cwt.verify(token, Buffer.from(secret, "hex")).then((verifyTest) => {
   console.log(verifyTest);
});
```


## cwt.decode(token)

Returns the decoded payload without verifying if the signature is valid.

Example:
```js
const decodeTest = cwt.decode(token).then((decodeTest) => {
  //  console.log(decodeTest);
});
```

# Errors:
Possible thrown Erros during verification. Tags might mismatch or the data handed to the functions might be invalid.

# Algorithms supported
SHA-256_64


# License
This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.


## Testdata

You can use the following data to test cwt.functions()
```js
via given examples from: https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token-08#appendix-A.4
const cwt = new Cborwebtoken();
const payload = { iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com", exp: 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from("0b71", "hex") };
const secret = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
const token = "d18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200";
````
