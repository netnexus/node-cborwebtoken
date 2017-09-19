/// <reference types="node" />
export declare class Cborwebtoken {
    mac(payload: object, secret: string | Buffer): Promise<Buffer>;
    decode(token: string): Promise<object>;
    verify(token: string | Buffer | object, secret: string | Buffer): Promise<Buffer>;
    private buildMap(obj);
    private unBuildMap(payload);
}
