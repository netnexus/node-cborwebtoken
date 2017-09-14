var cbor = require('cbor');
const cose = require('cose-js');
const jsonfile = require('jsonfile');
const base64url = require('base64url');

//those are using the given example (from: https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token-08#appendix-A.4) as their current default. Will change later on.
var claims = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7 };
var payload = { iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com", exp: 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from('0b71', 'hex') }

export class cborwebtoken {
    public async mac(payload: string | Buffer | object, secret: string | Buffer): Promise<Buffer> {
        let buf = await cose.mac.create(
            { 'p': { "alg": "SHA-256_64" } },
            payload,
            [{ 'key': secret }])
        var tag = (cbor.decode(buf).value[3]);
        tag = tag.slice(0, 8);
        buf = cbor.decode(buf);
        buf.value[3] = tag;
        buf = cbor.encode(buf);
        buf = buf.toString('hex');
        buf = 'd83d' + buf;
        return buf;
    }
}

function buildMap(obj: any): Map<string | number, any> {
    var m = new Map();
    for (var key of Object.keys(obj)) {
        if (Object.keys(claims).indexOf(key) > -1 && !(obj[claims[key]])) {
            m.set(claims[key], obj[key]);
        } else {
            if (Object.values(claims).indexOf(obj[key])) {
                if (parseInt(key)) {
                    m.set(parseInt(key), obj[key]);
                } else {
                    m.set(key, obj[key]);
                }
            }
        }
    }
    return cbor.encode(m);
}

//testing via given example (from: https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token-08#appendix-A.4 )
var tester = buildMap(payload);
let cwt = new cborwebtoken();
var secret = '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388';
const tokenResponse = cwt.mac(tester, Buffer.from(secret, 'hex')).then((tokenResponse) => {
    console.log(tokenResponse);
});
