"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// tslint:disable:object-literal-sort-keys
const chai_1 = require("chai");
require("mocha");
const KeyError_class_1 = require("../src/errors/KeyError.class");
const TokenError_class_1 = require("../src/errors/TokenError.class");
const index_1 = require("../src/index");
// tslint:disable-next-line:no-var-requires
const cbor = require("cbor");
describe("#mac", () => {
    it("should return the CborWebToken as a string", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const payload = {
            iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com",
            exp: 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from("0b71", "hex"),
        };
        const secret = Buffer.from("403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388", "hex");
        // act
        const token = await cwt.mac(payload, secret);
        // assert
        const expectedBase64 = Buffer.from("d83dd18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d0"
            + "2656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d"
            + "9f007420b7148093101ef6d789200", "hex")
            .toString("base64");
        chai_1.expect(token).to.eql(expectedBase64);
    });
    it("should replace payload keys", async () => {
        // arrange
        const secret = "my-secret";
        const payload = {
            iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com",
            exp: 1444064944, nbf: 1443944944, iat: 1443944944,
            cti: Buffer.from("0b71", "hex"), test: "test",
        };
        const payloadexpected = {
            1: "coap://as.example.com", 2: "erikw", 3: "coap://light.example.com",
            4: 1444064944, 5: 1443944944, 6: 1443944944,
            7: Buffer.from("0b71", "hex"), test: "test",
        };
        const cwt = new index_1.Cborwebtoken();
        // act
        const token = await cwt.mac(payload, secret);
        // assert
        const decodedcwt = cbor.decode(Buffer.from(token, "base64"));
        const actualpayload = cbor.decode(decodedcwt.value.value[2]);
        const arr = [];
        for (const key of Array.from(actualpayload.keys())) {
            arr.push(key.toString());
        }
        chai_1.expect(arr).to.eql(Object.keys(payloadexpected));
    });
    it("should throw KeyError because there's an invalid payload Key", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const secret = "my-secret";
        // act & assert
        try {
            await cwt.mac({ 1: "bad key" }, secret);
            throw new Error("'cwt.mac' should have thrown an error");
        }
        catch (err) {
            chai_1.expect(err).to.be.an.instanceOf(KeyError_class_1.KeyError);
        }
    });
    // TODO: Add test that keys like 1 in the payload throw an error when calling cwt.mac
});
describe("#decode", () => {
    it("should return the payload without verifying if the signature is valid. Here, payload is a map", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const token = "2D3RhEOhAQSgWFCnAXVjb2FwOi8vYXMuZXhhbXBsZS5jb20CZWVyaWt3A3gYY29hcDovL2x"
            + "pZ2h0LmV4YW1wbGUuY29tBBqRrXiwBRpWENnwBhpWENnwB0ILcUgJMQHvbXiSAA==";
        // act
        const payload = await cwt.decode(token);
        // assert
        chai_1.expect(payload).to.eql({
            iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com",
            exp: 2444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from("0b71", "hex"),
        });
    });
    // TODO: Add test with reverting payload keys back
});
describe("#decode", () => {
    // tslint:disable-next-line:max-line-length
    it("should return the payload without verifying if the signature is valid. Here, payload is an object", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const secret = "my-secret";
        const token = await cwt.mac({ test: "test" }, secret);
        // act
        const payload = await cwt.decode(token);
        // assert
        chai_1.expect(payload).to.eql({ test: "test" });
    });
    // TODO: Add test with reverting payload keys back
});
describe("#verify", () => {
    it("should return the payload if the signature is valid", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const payload = {
            iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com",
            exp: 2444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from("0b71", "hex"),
        };
        const secret = "my-secret";
        const token = await cwt.mac(payload, secret);
        // act
        const verifiedPayload = await cwt.verify(token, secret);
        // assert
        chai_1.expect(verifiedPayload).to.eql(payload);
    });
    it("should throw tag mismatch for invalid token", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const secret = "my-secret";
        const token = "2D3RhEOhAQSgQaBISq4BtGzpRSI=";
        // act & assert
        try {
            await cwt.verify(token, secret);
            throw new Error("'cwt.verify' should have thrown an error");
        }
        catch (err) {
            chai_1.expect(err.message).to.eql("Tag mismatch");
        }
    });
    it("should throw TokenError because exp is reached", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const secret = "my-secret";
        const token = "2D3RhEOhAQSgR6EEGj47KrBI6scaiqIJrRU="; // contains expired token 1044064944
        // act & assert
        try {
            await cwt.verify(token, secret);
            throw new Error("'cwt.verify' should have thrown an error");
        }
        catch (err) {
            chai_1.expect(err).to.be.an.instanceOf(TokenError_class_1.TokenError);
        }
    });
    it("should allow Tokens without exp", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const secret = "my-secret";
        const token = await cwt.mac({ test: "test" }, secret); // contains token w/o exp
        // act & assert
        const actualpayload = await cwt.verify(token, secret);
        chai_1.expect(actualpayload).to.eql({ test: "test" });
    });
});
//# sourceMappingURL=index.spec.js.map