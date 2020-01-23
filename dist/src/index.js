"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const KeyError_class_1 = require("./errors/KeyError.class");
const TokenError_class_1 = require("./errors/TokenError.class");
// tslint:disable-next-line:no-var-requires
const cbor = require("cbor");
// tslint:disable-next-line:no-var-requires
const cose = require("cose-js");
class Cborwebtoken {
    constructor() {
        /**
         * @see https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token-08#section-4
         */
        this.claims = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7 };
    }
    /**
     * Create a CborWebToken and return it as a base64 encoded string.
     *
     * @param {any} payload - data which should be included into the token.
     * @param {string | Buffer} secret - a private secret.
     */
    async mac(payload, secret) {
        const mappedPayload = cbor.encode(this.translateClaims(payload));
        const buf = await cose.mac.create({ p: { alg: "SHA-256_64" } }, mappedPayload, { key: secret });
        return Buffer.concat([Cborwebtoken.CWT_TAG, buf]).toString("base64");
    }
    /**
     * Return decoded payload of a token. Method does not check the validity of the
     * signature and thus just returns the decoded payload.
     *
     * @param {string} token - The token to be decoded as a base64 encoded string.
     */
    decode(token) {
        const newToken = cbor.decode(Buffer.from(token, "base64").slice(2));
        const newPayload = cbor.decode(newToken.value[2]);
        if (!(newPayload instanceof Map)) {
            return newPayload;
        }
        return this.revertClaims(newPayload);
    }
    /**
     * Check token signature and exp and return payload or throw an error if validation
     * fails.
     *
     * @param {string} token - The base64 encoded token to be decoded and verified.
     * @param {string | Buffer} secret - The secret used to encode the token.
     */
    async verify(token, secret) {
        const payload = cbor.decode(await cose.mac.read(Buffer.from(token, "base64").slice(2), secret));
        if (!(payload instanceof Map)) {
            return payload;
        }
        const exptime = payload.get(4);
        this.isExpired(exptime);
        return this.revertClaims(payload);
    }
    /**
     * Keys in obj which are claims will be replaced with numbers. E.g. {iss: "test"} will
     * become Map {1 => "test"}
     *
     * @param {any} obj payload
     */
    translateClaims(obj) {
        const result = new Map();
        for (const key of Object.keys(obj)) {
            if ((Object.values(this.claims).toString()).includes(key.toString())) {
                throw new KeyError_class_1.KeyError("Invalid payload key");
            }
            result.set(this.claims[key] ? this.claims[key] : key, obj[key]);
        }
        return result;
    }
    /**
     * Revert replacement of claims keys with numbers. E.g. Map {1 => "test"} will
     * become {iss: "test"}.
     *
     * @param {object} obj payload
     */
    revertClaims(obj) {
        const swappedClaims = this.swap(this.claims);
        const result = {};
        for (const key of obj.keys()) {
            if (swappedClaims[key]) {
                result[swappedClaims[key]] = obj.get(key);
            }
            else {
                result[key] = obj.get(key);
            }
        }
        return result;
    }
    /**
     * Helper to check if a timestamp is expired.
     *
     * @param {number} ts timestamp
     */
    isExpired(ts) {
        const now = Math.floor((new Date()).getTime() / 1000);
        if (ts < now) {
            throw new TokenError_class_1.TokenError("Token expired!");
        }
    }
    /**
     * Helper to invert objects: {1: "iss"} becomes {"iss": 1}.
     *
     * @param {any} obj
     */
    swap(obj) {
        const ret = {};
        // tslint:disable-next-line:forin
        for (const key in obj) {
            ret[obj[key]] = key;
        }
        return ret;
    }
}
exports.Cborwebtoken = Cborwebtoken;
/**
 * Tag for CWT
 */
Cborwebtoken.CWT_TAG = Buffer.from("d83d", "hex");
//# sourceMappingURL=index.js.map