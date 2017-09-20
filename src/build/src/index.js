"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const cbor = require("cbor");
const cose = require("cose-js");
class Cborwebtoken {
    // creates the CborWebToken using cose-js function and returns it as a string
    async mac(payload, secret) {
        const mappedPayload = this.buildMap(payload);
        let buf = await cose.mac.create({ p: { alg: "SHA-256_64" } }, mappedPayload, [{ key: secret }]);
        buf = buf.toString("hex");
        // adding prefix "d83d" (61) as we only use this
        buf = "d83d" + buf;
        return buf;
    }
    // calls cbor.decode to decode the given Token. Returns the decoded payload without verifying if the signature is valid.
    async decode(token) {
        const newToken = cbor.decode(token);
        // tslint:disable-next-line:no-console
        console.log(newToken);
        const newPayload = cbor.decode(newToken.value[2]);
        return this.unBuildMap(newPayload);
    }
    // also decodes the given Token but additionally checks if the signature is valid (via cose.mac.read). If not it will throw Error "Tag mismatch".
    async verify(token, secret) {
        let buf = await cose.mac.read(token, secret);
        buf = buf.toString("hex");
        return buf;
    }
    // Uses the payload to build a map with it's keys and values. Then replaces the original keys by using claim's values as new key if the original keys are the same.
    // Returns the CBOR encoded map
    buildMap(obj) {
        const claims = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7 };
        const m = new Map();
        for (const key of Object.keys(obj)) {
            if (key !== "1" || "2" || "3" || "4" || "5" || "6" || "7") {
                if (Object.keys(claims).indexOf(key) > -1 && !(obj[claims[key]])) {
                    m.set(claims[key], obj[key]);
                }
                else {
                    if (Object.values(claims).indexOf(obj[key])) {
                        // tslint:disable-next-line:radix
                        if (parseInt(key)) {
                            // tslint:disable-next-line:radix
                            m.set(parseInt(key), obj[key]);
                        }
                        else {
                            m.set(key, obj[key]);
                        }
                    }
                }
            }
            else {
                throw new Error("one or more keys are in range of 0-7 which is not allowed");
            }
        }
        return cbor.encode(m);
    }
    unBuildMap(payload) {
        const claimsreturn = { 1: "iss", 2: "sub", 3: "aud", 4: "exp", 5: "nbf", 6: "iat", 7: "cti" };
        const n = {};
        for (const key of payload.keys()) {
            if (key in claimsreturn) {
                n[claimsreturn[key]] = payload.get(key);
            }
            else {
                n[key] = payload.get(key);
            }
        }
        // tslint:disable-next-line:no-console
        console.log(n);
        return n;
    }
}
exports.Cborwebtoken = Cborwebtoken;
//# sourceMappingURL=index.js.map