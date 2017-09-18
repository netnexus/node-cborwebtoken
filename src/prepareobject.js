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
Object.defineProperty(exports, "__esModule", { value: true });
var cbor = require('cbor');
var cose = require('cose-js');
var jsonfile = require('jsonfile');
var base64url = require('base64url');
//those are using the given example (from: https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token-08#appendix-A.4) as their current default. Will change later on.
var claims = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7 };
var payload = { iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com", exp: 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from('0b71', 'hex') };
var cborwebtoken = (function () {
    function cborwebtoken() {
    }
    cborwebtoken.prototype.sign = function (payload, secret) {
        return __awaiter(this, void 0, void 0, function () {
            var mappedPayload, buf, tag;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        mappedPayload = this.buildMap(payload);
                        return [4 /*yield*/, cose.mac.create({ 'p': { "alg": "SHA-256_64" } }, mappedPayload, [{ 'key': secret }])];
                    case 1:
                        buf = _a.sent();
                        tag = (cbor.decode(buf).value[3]);
                        buf = cbor.decode(buf);
                        buf.value[3] = tag;
                        buf = cbor.encode(buf);
                        buf = buf.toString('hex');
                        buf = 'd83d' + buf;
                        return [2 /*return*/, buf];
                }
            });
        });
    };
    cborwebtoken.prototype.decode = function (token) {
        return __awaiter(this, void 0, void 0, function () {
            var buf;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, cbor.decode(token)];
                    case 1:
                        buf = _a.sent();
                        buf = buf.value[2];
                        buf = buf.toString('hex');
                        return [2 /*return*/, buf];
                }
            });
        });
    };
    cborwebtoken.prototype.verify = function (token, secret) {
        return __awaiter(this, void 0, void 0, function () {
            var buf;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, cose.mac.read(token, secret)];
                    case 1:
                        buf = _a.sent();
                        buf = buf.toString('hex');
                        return [2 /*return*/, buf];
                }
            });
        });
    };
    cborwebtoken.prototype.buildMap = function (obj) {
        var claims = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7 };
        var m = new Map();
        for (var _i = 0, _a = Object.keys(obj); _i < _a.length; _i++) {
            var key = _a[_i];
            if (Object.keys(claims).indexOf(key) > -1 && !(obj[claims[key]])) {
                m.set(claims[key], obj[key]);
            }
            else {
                if (Object.values(claims).indexOf(obj[key])) {
                    console.log(Object.values(claims).indexOf(obj[key]));
                    if (parseInt(key)) {
                        m.set(parseInt(key), obj[key]);
                    }
                    else {
                        m.set(key, obj[key]);
                    }
                }
            }
        }
        return cbor.encode(m);
    };
    return cborwebtoken;
}());
exports.cborwebtoken = cborwebtoken;
//testing via given example (from: https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token-08#appendix-A.4 )
var cwt = new cborwebtoken();
var secret = '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388';
var token = "d18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200";
// to test the following cwt.functions remove commentary for console.log debugging
var tokenResponse = cwt.sign(payload, secret).then(function (tokenResponse) {
    //  console.log(tokenResponse);
});
var decodeTest = cwt.decode(token).then(function (decodeTest) {
    //  console.log(decodeTest);
});
var verifyTest = cwt.verify(token, Buffer.from(secret, 'hex')).then(function (verifyTest) {
    // console.log(verifyTest);
});
//# sourceMappingURL=prepareobject.js.map