var cbor = require('cbor');
var base64 = require('base-64');

var claims = {iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5 , iat: 6, cti: 7};
var payload = {iss: 'test',exp: 'abc'}
//var headerparameters = ['alg', 'crit', 'content_type', 'kid', 'IV', 'Partial_IV', 'counter_signature'];
var header = { alg: 4};

function buildMap(obj) {
    for (var key of Object.keys(obj)){
        if((Object.keys(obj[key])).indexOf(Object.keys(claims)) {
            console.log(Object.keys(claims));
            console.log((Object.keys(payload[key])));
        //    if( [1, 2, 3, 4, 5, 6, 7].includes(claims.indexOf(key)+1)){
         //       var test = Object.keys(obj).reduce((map, key) => map.set(claims.indexOf(key)+1, obj[key]), new Map());
                test = cbor.encode(test);
       /*     }else {
                throw new Error ('invalid payload key!');
            }
        }else {
            throw new Error ('invalid payload key!');
        }
    }
    */
    return test;
    }
}
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
            return (console.log('wrong algorithm, try 17'));
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
const map = buildMap(payload);
var y = prepareItem(payload, header);
console.log(y);
y = wrapItem(y);
