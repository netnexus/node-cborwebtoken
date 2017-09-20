/// <reference types="node" />
export declare class Cborwebtoken {
    /**
     * creates the CborWebToken using cose-js function and returns it as a string
     * @param {obj} payload - The token which is going to be verified by using cose.mac.create
     * @param {string | Buffer} secret -
     * The Secret that's being fed into cose.mac.create (alongside payload) in order to build a cwt.
     */
    mac(payload: object, secret: string | Buffer): Promise<Buffer>;
    /**
     * Simple test to check if "cwt.decode" is working properly.
     * It does not check the validiity of the signature and thus just returns the decoded payload.
     * As we want the payload to have it's original values we also call the unBuildMap function
     * (with 'newPayload' as parameter) in the return statement
     * @param {obj} token - The token to be decoded.
     */
    decode(token: string): Promise<object>;
    /**
     * Calling function 'cose.mac.read' with our token and it's secret as parameters.
     * This will deliver either a 'Tag mismatch' Error,
     * or in case of no error the confirmation that the token is valid.
     * @param {obj} token - The token to be decoded and verified.
     * @param {string | Buffer} secret - The secret used to verify the token.
     */
    verify(token: string | Buffer | object, secret: string | Buffer): Promise<Buffer>;
    /**
     * Uses the payload to build a map with it's keys and values.
     * Then replaces the original keys by using claim's values as new key if the original keys are the same.
     * Finally returns the CBOR encoded map consisting of data of types string, number or any
     * @param {any} obj - any valid payload
     */
    private buildMap(obj);
    /**
     * Uses the payload of the previously build map to revert the changes to it's keys.
     * By restricting the use of numbers 1-7 as in the payload prior to building it
     * it is prevented that we have a duplicate there.
     * Thus we can revert any changes concerning those numbers by using the "claimsreturn" object beneath.
     * It can be considered the inverse function of buildmap.
     * Finally returns an object 'n' which is the original payload, before building a map.
     * @param {Map<string |number | any>} payload - any valid mapped payload
     */
    private unBuildMap(payload);
}
