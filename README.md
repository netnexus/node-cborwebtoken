# node-cborwebtoken

Under development, not ready for usage!

An implementation of CBOR Web Tokens for node (TypeScript, JavaScript).

This was developed against [draft-ietf-ace-cbor-web-token-08](https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token-08).

# Install
```bash
$ npm install ...
```

# Usage

## cwt.sign(payload, secret)

Returns the CborWebToken as a string.

Example:
```js
...
```

## cwt.verify(token, secret)

Returns the payload decoded if the signature (and, optionally, expiration, audience, issuer) are valid. If not, it will throw an error.

Example:
```js
...
```

## cwt.decode(token)

Returns the decoded payload without verifying if the signature is valid.

Example:
```js
...
```


# Errors:
...

# Algorithms supported
...


# License
This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
