/// <reference types="node" />
export declare class Cborwebtoken {
    /**
     * Tag for CWT
     */
    private static CWT_TAG;
    /**
     * @see https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token-08#section-4
     */
    private claims;
    /**
     * Create a CborWebToken and return it as a base64 encoded string.
     *
     * @param {any} payload - data which should be included into the token.
     * @param {string | Buffer} secret - a private secret.
     */
    mac(payload: any, secret: string | Buffer): Promise<string>;
    /**
     * Return decoded payload of a token. Method does not check the validity of the
     * signature and thus just returns the decoded payload.
     *
     * @param {string} token - The token to be decoded as a base64 encoded string.
     */
    decode(token: string): any;
    /**
     * Check token signature and exp and return payload or throw an error if validation
     * fails.
     *
     * @param {string} token - The base64 encoded token to be decoded and verified.
     * @param {string | Buffer} secret - The secret used to encode the token.
     */
    verify(token: string, secret: string | Buffer): Promise<any>;
    /**
     * Keys in obj which are claims will be replaced with numbers. E.g. {iss: "test"} will
     * become Map {1 => "test"}
     *
     * @param {any} obj payload
     */
    private translateClaims(obj);
    /**
     * Revert replacement of claims keys with numbers. E.g. Map {1 => "test"} will
     * become {iss: "test"}.
     *
     * @param {object} obj payload
     */
    private revertClaims(obj);
    /**
     * Helper to check if a timestamp is expired.
     *
     * @param {number} ts timestamp
     */
    private isExpired(ts);
    /**
     * Helper to invert objects: {1: "iss"} becomes {"iss": 1}.
     *
     * @param {any} obj
     */
    private swap(obj);
}
