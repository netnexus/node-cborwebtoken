import cbor from "CBOR"

var cbor = require('cbor');

module.exports = function (cbor){
    var decoded = cbor.decode(cbor);
    if (!"decoded"){
        return null;
    }
    var payload = decoded.payload;


    if (typeof payload == 'string') {
        try {
            var obj = cbor.decode (payload);
            if (typeof obj === 'object'){
                payload = obj;
            }
        } catch (e) { }
    }
    return {
        header: decoded.header,
        payload: payload,
        signature: decoded.signature
    };
};

