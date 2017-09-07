"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/*
var timespan = require('./lib/timespan');
var once = require('lodash.once');
var xtend = require('xtend');
*/
var cbor = require('cbor');
var numbers = ["1", "2", "3", "4", "5", "6", "7"];
var claims = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'cti'];
var payload = {
    iss: "test",
    exp: 1234567890
};
var i = 0;
function prepareItem(obj) {
    for (var _i = 0, _a = Object.keys(obj); _i < _a.length; _i++) {
        var key = _a[_i];
        var handle = claims.indexOf(key) + 1;
        obj[handle] = obj[key];
        delete (obj[key]);
    }
    return obj;
}
var x = prepareItem(payload);
var old = JSON.stringify(x).replace(/"/g, '');
var newArray = JSON.parse(old);
console.log(newArray);
//# sourceMappingURL=prepareobject.js.map