import { Field, Message, Type } from "protobufjs";

export const SymmetricCipherName = [
    'aes-256-cbc',
    'aes-256-ctr',
    'aes-256-ecb',
    'aes-256-gcm'
];

export enum SymmetricCipher {
    AES256CBC = 0,
    AES256CTR = 1,
    AES256ECB = 2,
    AES256GCM = 3,
};

export type EncryptInput = {
    cipher?: SymmetricCipher;
    data: Buffer;
    iv?: Buffer | null;
    key: Buffer;
}

export type EncryptOutput = {
    authTag?: Buffer;    
    cipher: SymmetricCipher;
    data: Buffer;
    iv: Buffer | null;
}

@Type.d("Envelope")
export class Envelope extends Message<Envelope> {
    @Field.d(1, SymmetricCipher)
    cipher: SymmetricCipher;

    @Field.d(2, "bytes")
    data: Buffer;

    @Field.d(3, "bytes", "optional")
    iv?: Buffer;

    @Field.d(4, "bytes", "optional")
    authTag: Buffer;
}