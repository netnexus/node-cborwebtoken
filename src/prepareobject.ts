var cbor = require('cbor');
const cose = require('cose-js');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
//var base64 = require('base-64');

var claims = {iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5 , iat: 6, cti: 7};
var payload = {iss: "coap://as.example.com" , sub: "erikw", aud: "coap://light.example.com", exp : 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from('0b71','hex')}
    
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
    console.log(COSE_Mac0);
    return cbor.encode(COSE_Mac0);
}
function wrapItem(obj){
    //wrap obj..
}
var tester = buildMap(payload);

cose.mac.create(
    { 'p':{"alg":"SHA-256_64"},'u':{}},
    tester,
    [{'key':Buffer.from("403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388", 'hex')}])
  .then((buf) => {
    console.log(buf.toString('hex'));
});
