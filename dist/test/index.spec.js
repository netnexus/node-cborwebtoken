"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = require("chai");
require("mocha");
const index_1 = require("../src/index");
// tslint:disable-next-line:no-var-requires
const cbor = require("cbor");
/**
 * creates the CborWebToken using cose-js function and returns it as a string
 * @param {obj} payload - The payload that is handed over in Order to be macced with the secret.
 * @param {string} secret -
 * The Secret that's being fed into cose.mac.create (alongside payload) in order to build a cwt.
 */
describe(".mac()", () => {
    it("should return the CborWebToken as a string", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        // tslint:disable-next-line:object-literal-sort-keys
        const payload = { iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com",
            exp: 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from("0b71", "hex") };
        const secret = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
        // act
        const test = await cwt.mac(payload, Buffer.from(secret, "hex"));
        // assert
        // tslint:disable-next-line:max-line-length
        chai_1.expect(test).to.eql("d83dd18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200");
    });
});
/**
 * Simple test to check if "cwt.decode" is working properly.
 * It does not check the validiity of the signature and thus just returns the decoded payload.
 * @param {obj} token - The token to be decoded.
 */
describe(".decode", () => {
    it("should return the payload without verifying if the signature is valid", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        // tslint:disable-next-line:max-line-length
        const token = "d18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a91ad78b0051a5610d9f0061a5610d9f007420b7148093101ef6d789200";
        // act
        const payload = await cwt.decode(token);
        // assert
        // tslint:disable-next-line:max-line-length
        chai_1.expect(payload).to.eql(cbor.decode("A76369737375636F61703A2F2F61732E6578616D706C652E636F6D63737562656572696B77636175647818636F61703A2F2F6C696768742E6578616D706C652E636F6D636578701A91ad78B0636E62661A5610D9F0636961741A5610D9F063637469420B71"));
    });
});
/**
 * Checks if the signature is valid by calling "cwt.verify".
 * If it is, the payload is returned, if not it throws an Error "Tag mismatch".
 * @param {obj} token - The token which is going to be verified by using cose.mac.read
 * @param {string} secret -
 * The Secret that's being fed into cose.mac.read (alongside token) in order to decode and verify it.
 */
describe(".verify", () => {
    it("should return the payload if the signature is valid. If not it will throw an Error", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        // tslint:disable-next-line:max-line-length
        const token = "d18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200";
        const secret = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
        // act
        const payload = await cwt.verify(token, Buffer.from(secret, "hex"));
        // assert
        // tslint:disable-next-line:max-line-length
        chai_1.expect(payload).to.equal("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71");
    });
});
/**
 * building a cwt from the ground by handing over payload and secret to "cwt.mac".
 * You then decode the CWT and compare it's payload with the expected one,
 * where the keys should be replaced by the given numbers in payloadexpected (via cwt.mac).
 * @param {obj} token - The token which is going to be verified by using cose.mac.read
 * @param {string} secret -
 * The Secret that's being fed into cose.mac.read (alongside token) in order to decode and verify it.
 */
describe("payloadcheck", () => {
    it("should replace payload keys", async () => {
        // arrange
        const secret = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
        // tslint:disable-next-line:object-literal-sort-keys
        const payload = { iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com",
            exp: 1444064944, nbf: 1443944944, iat: 1443944944,
            cti: Buffer.from("0b71", "hex"), test: "test" };
        const payloadexpected = { 1: "coap://as.example.com", 2: "erikw", 3: "coap://light.example.com",
            4: 1444064944, 5: 1443944944, 6: 1443944944,
            7: Buffer.from("0b71", "hex"), test: "test" };
        const cwt = new index_1.Cborwebtoken();
        // act
        const token = await cwt.mac(payload, Buffer.from(secret, "hex"));
        // assert
        const decodedcwt = cbor.decode(token);
        const actualpayload = cbor.decode(decodedcwt.value.value[2]);
        const arr = [];
        for (const key of Array.from(actualpayload.keys())) {
            arr.push(key.toString());
        }
        chai_1.expect(arr).to.eql(Object.keys(payloadexpected));
    });
});
//# sourceMappingURL=index.spec.js.map