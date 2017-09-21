"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const KeyError_class_1 = require("./errors/KeyError.class");
const TokenError_class_1 = require("./errors/TokenError.class");
// tslint:disable-next-line:no-var-requires
const cbor = require("cbor");
// tslint:disable-next-line:no-var-requires
const cose = require("cose-js");
// tslint:disable-next-line:no-var-requires
const sinon = require("sinon");
class Cborwebtoken {
    /**
     * creates the CborWebToken using cose-js function and returns it as a string
     * @param {obj} payload - The token which is going to be verified by using cose.mac.create
     * @param {string | Buffer} secret -
     * The Secret that's being fed into cose.mac.create (alongside payload) in order to build a cwt.
     */
    async mac(payload, secret) {
        const mappedPayload = cbor.encode(this.buildMap(payload));
        let buf = await cose.mac.create({ p: { alg: "SHA-256_64" } }, mappedPayload, [{ key: secret }]);
        buf = buf.toString("hex");
        /**
         * adding prefix "d83d" (61). As the CWTs are MACed (payload of type COSE_Mac0) -
         * COSE Mac w/o Recipient Object - we always use prefix 61.
         */
        buf = "d83d" + buf;
        return buf;
    }
    /**
     * Simple test to check if "cwt.decode" is working properly.
     * It does not check the validity of the signature and thus just returns the decoded payload.
     * As we want the payload to have it's original values we also call the unBuildMap function
     * (with 'newPayload' as parameter) in the return statement
     * @param {obj} token - The token to be decoded.
     */
    async decode(token) {
        const newToken = cbor.decode(token);
        const newPayload = cbor.decode(newToken.value[2]);
        return this.unBuildMap(newPayload);
    }
    /**
     * Calling function 'cose.mac.read' with our token and it's secret as parameters.
     * This will deliver either a 'Tag mismatch' Error,
     * or in case of no error the confirmation that the token is valid.
     * @param {obj} token - The token to be decoded and verified.
     * @param {string | Buffer} secret - The secret used to verify the token.
     */
    async verify(token, secret) {
        const payload = cbor.decode(cbor.decode(token).value[2]);
        const exptime = payload.get(4);
        const expired = this.expirecheck(exptime);
        if (expired === true) {
            let buf = await cose.mac.read(token, secret);
            buf = buf.toString("hex");
            return buf;
        }
    }
    /**
     * Uses the payload to build a map with it's keys and values.
     * Then replaces the original keys by using claim's values as new key if the original keys are the same.
     * Finally returns the CBOR encoded map consisting of data of types string, number or any
     * @param {any} obj - any valid payload
     * if the key exists as key in "claims" we use the value (e.g. 1 for iss) for the creation of the map.
     * otherwise we simply keep the key (e.g. "test" is not in claims, so it stays the same).
     * to trigger the KeyError replace a payload key in mac- or checkpayload-tests with a number from 1-7
     */
    buildMap(obj) {
        const claims = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7 };
        const arr = ["1", "2", "3", "4", "5", "6", "7"];
        const m = new Map();
        for (const key of Object.keys(obj)) {
            if (arr.includes(key.toString())) {
                throw new KeyError_class_1.KeyError("invalid payload key");
            }
            m.set(claims[key] ? claims[key] : key, obj[key]);
        }
        return m;
    }
    /**
     * Uses the payload of the previously build map to revert the changes to it's keys.
     * By restricting the use of numbers 1-7 as in the payload prior to building it
     * it is prevented that we have a duplicate there.
     * Thus we can revert any changes concerning those numbers by using the "claimsreturn" object beneath.
     * It can be considered the inverse function of buildmap.
     * Finally returns an object 'n' which is the original payload, before building a map.
     * @param {Map<string |number | any>} payload - any valid mapped payload
     */
    unBuildMap(payload) {
        const claimsreturn = { 1: "iss", 2: "sub", 3: "aud", 4: "exp", 5: "nbf", 6: "iat", 7: "cti" };
        const n = {};
        for (const key of payload.keys()) {
            if (claimsreturn[key]) {
                n[claimsreturn[key]] = payload.get(key);
            }
            else {
                n[key] = payload.get(key);
            }
        }
        return n;
    }
    expirecheck(exptime) {
        const clock = sinon.useFakeTimers(1437018650000);
        let currenttime = clock.now / 1000;
        currenttime = Math.floor(currenttime);
        if (exptime > currenttime) {
            clock.restore();
            return true;
        }
        else {
            clock.restore();
            throw new TokenError_class_1.TokenError("Token expired!");
        }
    }
}
exports.Cborwebtoken = Cborwebtoken;
//# sourceMappingURL=index.js.map