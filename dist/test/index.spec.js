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
    it("should return the map payload without verifying if the signature is valid.", async () => {
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
    it("should return the object payload without verifying if the signature is valid.", async () => {
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
    it("should throw error for empty token string", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const secret = "my-secret";
        // act & assert
        try {
            await cwt.verify("", secret);
            throw new Error("'cwt.verify' should have thrown an error");
        }
        catch (err) {
            chai_1.expect(err).to.be.an.instanceOf(Error);
        }
    });
    it("should throw error for undefined token", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const secret = "my-secret";
        // act & assert
        try {
            await cwt.verify(undefined, secret);
            throw new Error("'cwt.verify' should have thrown an error");
        }
        catch (err) {
            chai_1.expect(err).to.be.an.instanceOf(Error);
        }
    });
    it("should throw error for null token", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const secret = "my-secret";
        // act & assert
        try {
            await cwt.verify(null, secret);
            throw new Error("'cwt.verify' should have thrown an error");
        }
        catch (err) {
            chai_1.expect(err).to.be.an.instanceOf(Error);
        }
    });
});
// Key material from RFC 8392 Appendix A.2 / cose-js examples
const ecPrivateKey = {
    d: Buffer.from("6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19", "hex"),
};
const ecPublicKey = {
    x: Buffer.from("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f", "hex"),
    y: Buffer.from("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9", "hex"),
};
describe("#sign", () => {
    it("should return a signed CborWebToken as a string", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const payload = {
            iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com",
            exp: 2444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from("0b71", "hex"),
        };
        // act
        const token = await cwt.sign(payload, ecPrivateKey);
        // assert
        chai_1.expect(token).to.be.a("string");
        chai_1.expect(token.length).to.be.greaterThan(0);
    });
    it("should replace payload claims with numeric keys in the signed token", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const payload = {
            iss: "coap://as.example.com", sub: "erikw",
            exp: 2444064944, test: "test",
        };
        // act
        const token = await cwt.sign(payload, ecPrivateKey);
        // assert
        const decoded = cbor.decode(Buffer.from(token, "base64").slice(2));
        const actualPayload = cbor.decode(decoded.value[2]);
        chai_1.expect(actualPayload.get(1)).to.eql("coap://as.example.com");
        chai_1.expect(actualPayload.get(2)).to.eql("erikw");
        chai_1.expect(actualPayload.get(4)).to.eql(2444064944);
        chai_1.expect(actualPayload.get("test")).to.eql("test");
    });
    it("should throw KeyError because there's an invalid payload key", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        // act & assert
        try {
            await cwt.sign({ 1: "bad key" }, ecPrivateKey);
            throw new Error("'cwt.sign' should have thrown an error");
        }
        catch (err) {
            chai_1.expect(err).to.be.an.instanceOf(KeyError_class_1.KeyError);
        }
    });
    it("should throw an error for an unsupported algorithm", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        // act & assert
        try {
            await cwt.sign({ test: "test" }, ecPrivateKey, "RS256");
            throw new Error("'cwt.sign' should have thrown an error");
        }
        catch (err) {
            chai_1.expect(err).to.be.an.instanceOf(Error);
            chai_1.expect(err.message).to.include("Unsupported algorithm");
        }
    });
});
describe("#verifySign", () => {
    it("should return the payload if the ECDSA signature is valid", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const payload = {
            iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com",
            exp: 2444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from("0b71", "hex"),
        };
        const token = await cwt.sign(payload, ecPrivateKey);
        // act
        const verifiedPayload = await cwt.verifySign(token, ecPublicKey);
        // assert
        chai_1.expect(verifiedPayload).to.eql(payload);
    });
    it("should allow signed tokens without exp claim", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const token = await cwt.sign({ test: "test" }, ecPrivateKey);
        // act
        const verifiedPayload = await cwt.verifySign(token, ecPublicKey);
        // assert
        chai_1.expect(verifiedPayload).to.eql({ test: "test" });
    });
    it("should throw TokenError because exp is reached", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const expiredPayload = { exp: 1044064944 }; // expired timestamp
        const token = await cwt.sign(expiredPayload, ecPrivateKey);
        // act & assert
        try {
            await cwt.verifySign(token, ecPublicKey);
            throw new Error("'cwt.verifySign' should have thrown an error");
        }
        catch (err) {
            chai_1.expect(err).to.be.an.instanceOf(TokenError_class_1.TokenError);
        }
    });
    it("should throw an error when verifying with a wrong public key", async () => {
        // arrange
        const cwt = new index_1.Cborwebtoken();
        const token = await cwt.sign({ test: "test" }, ecPrivateKey);
        const wrongPublicKey = {
            x: Buffer.from("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff", "hex"),
            y: Buffer.from("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e", "hex"),
        };
        // act & assert
        try {
            await cwt.verifySign(token, wrongPublicKey);
            throw new Error("'cwt.verifySign' should have thrown an error");
        }
        catch (err) {
            chai_1.expect(err).to.be.an.instanceOf(Error);
        }
    });
});
//# sourceMappingURL=index.spec.js.map