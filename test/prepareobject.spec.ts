import { expect } from "chai";
import "mocha";
import { cose } from "cose-js";
import { cborwebtoken } from "../src/prepareobject"
var cbor = require('cbor');
const cose = require('cose-js');
const jsonfile = require('jsonfile');
const base64url = require('base64url');

describe('.sign()', () => {
    it('should return the CborWebToken as a string', async() =>{
        //arrange
        let cwt = new cborwebtoken();
        var payload = { iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com", exp: 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from('0b71', 'hex') }
        var secret = '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388';
        //act
        const test =  await cwt.sign(payload, Buffer.from(secret, 'hex'));
        //assert
        expect(test).to.eql('d83dd18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200');
    })
})

describe('.decode', () => {
    it('should return the payload without verifying if the signature is valid', async() =>{
        //arrange
        let cwt = new cborwebtoken();
        const token = "d18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200";
        //act
        const payload = await cwt.decode(token);
        //assert
        expect(payload).to.eql("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71");
    })
})

describe('.verify', () => {
    it('should return the payload if the signature is valid. If not it will throw an Error', async()=> {
        //arrange
        let cwt = new cborwebtoken();
        const token = "d18443a10104a05850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200";
        var secret = '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388';   
        //act
        const payload = await cwt.verify(token, Buffer.from(secret,'hex'));
        //assert
        expect(payload).to.eql("a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71");
    })
})
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
describe('payloadcheck',()=>{
    it('should replace payload keys', async ()=>{
        //arrange
        var secret = '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388';   
        var payload = { iss: "coap://as.example.com", sub: "erikw", aud: "coap://light.example.com", exp: 1444064944, nbf: 1443944944, iat: 1443944944, cti: Buffer.from('0b71', 'hex'), test: "test"}
        var payloadexpected = { 1: "coap://as.example.com", 2: "erikw", 3: "coap://light.example.com", 4: 1444064944, 5: 1443944944, 6: 1443944944, 7: Buffer.from('0b71', 'hex'), test: "test" }
        let cwt = new cborwebtoken();
        //act
        var token =  await cwt.sign(payload, Buffer.from(secret, 'hex'));
        //assert
        var decodedcwt = cbor.decode(token);
        var actualpayload = cbor.decode(decodedcwt["value"]["value"][2]);
        var arr = [];
        for (let key of Array.from(actualpayload.keys())){
            arr.push(key.toString());
        }
        expect(arr).to.eql(Object.keys(payloadexpected));
    })
})