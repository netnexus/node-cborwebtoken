# node-cborwebtoken
[![Build Status](https://travis-ci.org/netnexus/node-cborwebtoken.svg?branch=master)](https://travis-ci.org/netnexus/node-cborwebtoken)

An implementation of CBOR Web Tokens for node (TypeScript, JavaScript).

This was developed against [draft-ietf-ace-cbor-web-token-08](https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token-08).

# Install
```bash
$ npm install @netnexus/node-cborwebtoken
```

# Usage

## cwt.mac(payload, secret)

Returns a CWT (Cbor Web Token) as a base64 encoded string.

Example:
```js
const payload = { iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com", exp: 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from("0b71", "hex") };
const secret = "my-test-secret";
cwt.mac(payload, secret).then((token) => {
    console.log(token);
});
```

## cwt.verify(token, secret)

Returns the decoded payload if the signature (and optionally expiration) are valid. If not, it will throw an error.

Example:
```js
const token = "2D3RhEOhAQSgWFCnAXVjb2FwOi8vYXMuZXhhbXBsZS5jb20CZWVyaWt3A3gYY29hcDovL2x"
    + "pZ2h0LmV4YW1wbGUuY29tBBqRrXiwBRpWENnwBhpWENnwB0ILcUgJMQHvbXiSAA==";
const secret = "my-invalid-secret";
cwt.verify(token, secret).then((payload) => {
   console.log(payload);
});
```


## cwt.decode(token)

Returns the decoded payload without verifying if the signature is valid.

Example:
```js
const token = "2D3RhEOhAQSgWFCnAXVjb2FwOi8vYXMuZXhhbXBsZS5jb20CZWVyaWt3A3gYY29hcDovL2x"
    + "pZ2h0LmV4YW1wbGUuY29tBBqRrXiwBRpWENnwBhpWENnwB0ILcUgJMQHvbXiSAA==";
const payload = cwt.decode(token);
console.log(payload);
```

# Errors
Possible errors thrown when creating a token:
- `KeyError` in case a payload Key is invalid

Possible errors thrown when verifying a token:
- `TokenError` in case the token is expired
- Tag mismatch (thrown by underlying cose-js lib)


# Algorithms supported
SHA-256_64


# License
This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
