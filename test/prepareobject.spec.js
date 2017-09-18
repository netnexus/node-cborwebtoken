"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = y[op[0] & 2 ? "return" : op[0] ? "throw" : "next"]) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [0, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
var chai_1 = require("chai");
require("mocha");
var prepareobject_1 = require("../src/prepareobject");
var cbor = require('cbor');
var cose = require('cose-js');
var jsonfile = require('jsonfile');
var base64url = require('base64url');
describe('.sign()', function () {
    it('should return the CborWebToken as a string', function () { return __awaiter(_this, void 0, void 0, function () {
        var cwt, payload, secret, test;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cwt = new prepareobject_1.cborwebtoken();
                    payload = { iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com", exp: 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from('0b71', 'hex') };
                    secret = '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388';
                    return [4 /*yield*/, cwt.sign(payload, Buffer.from(secret, 'hex'))];
                case 1:
                    test = _a.sent();
                    //assert
                    chai_1.expect(test).to.eql('d83dd18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200');
                    return [2 /*return*/];
            }
        });
    }); });
});
describe('.decode', function () {
    it('should return the payload without verifying if the signature is valid', function () { return __awaiter(_this, void 0, void 0, function () {
        var cwt, token, payload;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cwt = new prepareobject_1.cborwebtoken();
                    token = "d18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200";
                    return [4 /*yield*/, cwt.decode(token)];
                case 1:
                    payload = _a.sent();
                    //assert
                    chai_1.expect(payload).to.eql("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71");
                    return [2 /*return*/];
            }
        });
    }); });
});
describe('.verify', function () {
    it('should return the payload if the signature is valid. If not it will throw an Error', function () { return __awaiter(_this, void 0, void 0, function () {
        var cwt, token, secret, payload;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cwt = new prepareobject_1.cborwebtoken();
                    token = "d18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200";
                    secret = '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388';
                    return [4 /*yield*/, cwt.verify(token, Buffer.from(secret, 'hex'))];
                case 1:
                    payload = _a.sent();
                    //assert
                    chai_1.expect(payload).to.eql("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71");
                    return [2 /*return*/];
            }
        });
    }); });
});
/*
describe('.verify',()=>{
    it('should return an Error if the signature is invalid.', async()=>{
        //arrange
        let cwt = new cborwebtoken();
        const token = "d18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200";
        var secret = '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388';
        //act
        try{
            await cwt.verify(token, Buffer.from(secret, 'hex'));
            throw new Error('Tag mismatch');
        //assert
        }catch (err) {
            expect(err.message).to.eq("Tag mismatch");
        }
    })
    })
*/
describe('payloadcheck', function () {
    it('should return an OK if the payload is valid', function () { return __awaiter(_this, void 0, void 0, function () {
        var secret, claims, payload, cwt, test, test2, test3, test4, _i, _a, key;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    secret = '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388';
                    claims = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7 };
                    payload = { iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com", exp: 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from('0b71', 'hex') };
                    cwt = new prepareobject_1.cborwebtoken();
                    return [4 /*yield*/, cwt.sign(payload, Buffer.from(secret, 'hex'))];
                case 1:
                    test = _b.sent();
                    test2 = cbor.decode(test);
                    test3 = test2["value"]["value"][2];
                    test4 = cbor.decode(test3);
                    for (_i = 0, _a = Array.from(test4.keys()); _i < _a.length; _i++) {
                        key = _a[_i];
                        console.log(key);
                        console.log(test4.get(key));
                        console.log(Object.keys(claims)[Object.values(payload).indexOf(test4.get(key))]);
                        console.log(Object.keys(payload[test4.get(key)]));
                        //expect(test4.get(key)).to.eql(payload.key[claims[value].key]);
                        //expect(Object.keys(claims)[Object.values(payload).indexOf(test4.get(key))]).to.eql.(Object.keys(payload[test4.get(key)]))
                    }
                    chai_1.expect(test4).to.eql(test4);
                    return [2 /*return*/];
            }
        });
    }); });
});
//# sourceMappingURL=prepareobject.spec.js.map