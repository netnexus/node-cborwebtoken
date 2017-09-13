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
//var base64 = require('base-64');
var claims = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7 };
var payload = { iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com", exp: 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from('0b71', 'hex') };
//var headerparameters = ['alg', 'crit', 'content_type', 'kid', 'IV', 'Partial_IV', 'counter_signature'];
var header = { alg: 4 };
function buildMap(obj) {
    var m = new Map();
    for (var _i = 0, _a = Object.keys(obj); _i < _a.length; _i++) {
        var key = _a[_i];
        if (Object.keys(claims).indexOf(key) > -1 && !(obj[claims[key]])) {
            m.set(claims[key], obj[key]);
        }
        else {
            if (Object.values(claims).indexOf(obj[key])) {
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
}
function preparepayload(obj) {
    //replacing claims with their respective ids
    for (var _i = 0, _a = Object.keys(obj); _i < _a.length; _i++) {
        var key = _a[_i];
        /*       var handle = claims.indexOf(key)+1;
               obj[handle] = obj[key];
               delete(obj[key]);
       }*/
        return obj;
    }
}
function prepareItem(obj, header) {
    obj = buildMap(obj);
    //preparing header
    for (var _i = 0, _a = Object.keys(header); _i < _a.length; _i++) {
        var key = _a[_i];
        if (header[key] != 4) {
            return (console.log('wrong algorithm, try 4'));
        }
        else {
            //putting header and payload together
            var COSE_Mac0 = [header, obj];
        }
    }
    //encoding the newly assembled Object
    console.log(COSE_Mac0);
    return cbor.encode(COSE_Mac0);
}
function wrapItem(obj) {
    //wrap obj..
}
var tester = buildMap(payload);
var cborwebtoken = (function () {
    function cborwebtoken() {
    }
    cborwebtoken.prototype.mac = function (payload, secret) {
        return __awaiter(this, void 0, void 0, function () {
            var buf, tag;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, cose.mac.create({ 'p': { "alg": "SHA-256_64" } }, payload, [{ 'key': secret }])];
                    case 1:
                        buf = _a.sent();
                        console.log(secret);
                        tag = (cbor.decode(buf).value[3]);
                        tag = tag.slice(0, 8);
                        buf = cbor.decode(buf);
                        buf.value[3] = tag;
                        buf = cbor.encode(buf);
                        buf = buf.toString('hex');
                        return [2 /*return*/, buf];
                }
            });
        });
    };
    return cborwebtoken;
}());
exports.cborwebtoken = cborwebtoken;
var cwt = new cborwebtoken();
var secret = '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388';
var tokenResponse = cwt.mac(tester, Buffer.from(secret, 'hex')).then(function (tokenResponse) {
    console.log(tokenResponse);
});
//# sourceMappingURL=prepareobject.js.map