var cbor = require('cbor');
var cose = require('cose-js');
//var base64 = require('base-64');

var claims = {iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5 , iat: 6, cti: 7};
var payload = {iss: "test" , 3: "abc", undefined: "wasd", aud : "try", 123920: "mk"}
    
//var headerparameters = ['alg', 'crit', 'content_type', 'kid', 'IV', 'Partial_IV', 'counter_signature'];
var header = { alg: 4};

function buildMap(obj:any): Map<string | number, any> {
    var m = new Map();
    for (var key of Object.keys(obj)){
        if(Object.keys(claims).indexOf(key) >-1 && !(obj[claims[key]])) {
            m.set(claims[key], obj[key]);
        }else{
            if (Object.values(claims).indexOf(obj[key])){
                if (parseInt(key)){
                    m.set(parseInt(key), obj[key]);
                }else{
                    m.set(key, obj[key]);
                }
            }
        }
    }
return cbor.encode(m);
}

function preparepayload(obj) {
    //replacing claims with their respective ids
    for (var key of Object.keys(obj)){
     /*       var handle = claims.indexOf(key)+1;
            obj[handle] = obj[key];
            delete(obj[key]);
    }*/
    return obj;
    }
}


function prepareItem(obj, header){
    obj = buildMap(obj);
    //preparing header
    for (var key of Object.keys(header)){
        if (header[key] != 4){
            return (console.log('wrong algorithm, try 4'));
        }
        else{
            //putting header and payload together
            var COSE_Mac0 = [ header, obj];
        }
    }
    //encoding the newly assembled Object
    return cbor.encode(COSE_Mac0);
}





function wrapItem(obj){
    //wrap obj..
}
const tester = buildMap(payload);
var tester2 = cose.doMac(payload,17);
console.log((tester));