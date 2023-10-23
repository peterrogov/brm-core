import { Test, TestingModule } from '@nestjs/testing';
import { randomBytes } from 'crypto';
import { DEFAULT_SYMMETRIC_CIPHER, PBKF2_SALT_SIZE } from './symmetric-encryption.constants';
import { UnsupportedCipherError } from './symmetric-encryption.errors';
import { SymmetricEncryptionService } from './symmetric-encryption.service';
import { EncryptOutput, SymmetricCipher } from './symmetric-encryption.types';

describe('SymmetricEncryptionService', () => {
    let service: SymmetricEncryptionService;

    beforeEach(async () => {
        const app: TestingModule = await Test.createTestingModule({
            providers: [SymmetricEncryptionService],
        }).compile();

        service = app.get<SymmetricEncryptionService>(SymmetricEncryptionService);
    });

    describe('Key generations', () => {
        it('should generate key correctly', () => {
            const cipher = SymmetricCipher.AES256CBC;
            const key = service.generateKey(cipher);
            // AES256CBC operates on 256 bit (32 byte) keys
            expect(key.length).toEqual(32);
        });

        it('should fail with unsupported cipher', () => {
            const test = () => service.generateKey(10 as SymmetricCipher);
            expect(test).toThrowError(UnsupportedCipherError);
        });

        it('should generate iv correctly', () => {
            const cipher = SymmetricCipher.AES256CBC;
            const iv = service.getIV(cipher);
            expect(iv).toBeDefined();
            // IV length for AES256CBC is 16 bytes
            expect(iv?.length).toEqual(16);
        });

        it('should return null IV for ciphers that do not support IV', () => {
            const iv = service.getIV(SymmetricCipher.AES256ECB);
            expect(iv).toBeNull();
        });

        it('should get correct key buffer without salt', () => {
            const key = Buffer.from('secret');
            const expected = "c4937a9129730463ade96e842bc9c5fe6e108ab6a14730a5158f476c78f89039";
            const bufferedKey = service.getBufferedKey(key).toString("hex");
            expect(bufferedKey).toEqual(expected);
        });

        it('should return same buffered key for same input with the same salt', () => {
            const key = randomBytes(64).toString("hex");
            const salt = randomBytes(PBKF2_SALT_SIZE);
            const bufferedKey1 = service.getBufferedKey(key, salt).toString("hex");
            const bufferedKey2 = service.getBufferedKey(key, salt).toString("hex");
            expect(bufferedKey1).toEqual(bufferedKey2);
        });

        it('should return different buffered key for same input with different salt', () => {
            const key = randomBytes(64).toString("hex");
            const salt1 = randomBytes(PBKF2_SALT_SIZE);
            const salt2 = randomBytes(PBKF2_SALT_SIZE);
            const bufferedKey1 = service.getBufferedKey(key, salt1).toString("hex");
            const bufferedKey2 = service.getBufferedKey(key, salt2).toString("hex");
            expect(bufferedKey1).not.toEqual(bufferedKey2);
        });

        it('should work with salt provided as string', () => {
            const key = randomBytes(64).toString("hex");
            const salt = randomBytes(PBKF2_SALT_SIZE / 2).toString("hex");
            const bufferedKey = service.getBufferedKey(key, salt).toString("hex");
            expect(bufferedKey).toBeTruthy();
        });

        it('should fail to generate buffered key with a salt of invalid size', () => {
            const key = randomBytes(64).toString("hex");
            const salt = randomBytes(PBKF2_SALT_SIZE * 2);
            const test = () => service.getBufferedKey(key, salt);
            expect(test).toThrowError();
        });

        it('should fail GCM decryption if encrypted data was modified', () => {
            const cipher = SymmetricCipher.AES256GCM;
            const key = service.generateKey(cipher);
            const data = randomBytes(64);
            const encrypted = service.encrypt({ key, data, cipher });
            encrypted.data.set(randomBytes(8), 0); // tamper with encrypted data
            const test = () => service.decrypt(key, encrypted);
            expect(test).toThrow(/unable to authenticate data/g);
        });

        it('should enforce random IV in GCM mode', () => {
            const cipher = SymmetricCipher.AES256GCM;
            const key = service.generateKey(cipher);
            const data = randomBytes(64);
            const test = () => service.encrypt({ key, data, cipher, iv: service.getIV(cipher) });
            expect(test).toThrowError(/In GCM mode, do not manually set the IV/gi);
        });
    });

    describe("Secure hashing", () => {
        it('should compute hash', () => {
            const data = Buffer.from(randomBytes(64));
            const hash = service.secureHash(data);
            expect(hash).toBeTruthy();
        });

        it('should validate hash', () => {
            const data = Buffer.from(randomBytes(64));
            const hash = service.secureHash(data);
            const isValid = service.validateHash(data, hash);
            expect(isValid).toBe(true);
        });

        it('should return false if hash is not valid', () => {
            const data = randomBytes(64);
            const otherData = randomBytes(64);
            const hash = service.secureHash(data);
            const isValid = service.validateHash(otherData, hash);
            expect(isValid).toBe(false);
        });

        it('should fail if value is falsy', () => {
            const data: Buffer | null = null;
            const test = () => service.secureHash(data as unknown as Buffer);
            expect(test).toThrowError();
        });

        it('should fail if value length is 0', () => {
            const data = Buffer.alloc(0)
            const test = () => service.secureHash(data);
            expect(test).toThrowError();
        });
    });

    describe("Value encryption", () => {
        const sample = randomBytes(64);
        let iv: Buffer | null;
        let encrypted: EncryptOutput;
        let key: Buffer;

        beforeAll(() => {
            iv = service.getIV();
            key = service.getBufferedKey("secret");
        });

        it("should encrypt value", () => {
            encrypted = service.encrypt({ key, data: sample });
            expect(Buffer.isBuffer(encrypted.data)).toBeTruthy();
            expect(encrypted.data.compare(sample)).not.toBe(0);
        });

        it("should decrypt value", () => {
            const decrypted = service.decrypt(key, encrypted);
            expect(Buffer.isBuffer(decrypted)).toBe(true);
            expect(decrypted.compare(sample)).toBe(0);
        });

        it("should fail to encrypt with wrong IV", () => {
            const test1 = () => service.encrypt({ key, data: sample, iv: Buffer.alloc(0) });
            expect(test1).toThrowError();
            const test2 = () => service.encrypt({ key, data: sample, iv: randomBytes(16), cipher: SymmetricCipher.AES256ECB });
            expect(test2).toThrowError();
        });

        it("should fail to decrypt with wrong IV", () => {
            const test1 = () => service.decrypt(key, { data: sample, iv: Buffer.alloc(0), cipher: DEFAULT_SYMMETRIC_CIPHER });
            expect(test1).toThrowError();
        });
    });

    describe("Envelope encryption and encoding", () => {
        const sample = randomBytes(64);
        let iv: Buffer | null;
        let key: Buffer;
        let encodedEnvelope: Buffer;
        let encrypted: EncryptOutput;
        beforeAll(() => {
            iv = service.getIV();
            key = service.getBufferedKey("secret");
        });

        it('should encode envelope', () => {
            encrypted = service.encrypt({ key, data: sample });
            encodedEnvelope = service.encodeEnvelope(encrypted);
            expect(Buffer.isBuffer(encodedEnvelope) && encodedEnvelope.length > 0).toBe(true);
        });

        it('should decode envelope', () => {
            const decodedEnvelope = service.decodeEnvelope(encodedEnvelope);
            expect(decodedEnvelope.cipher).toBe(encrypted.cipher);
            expect(decodedEnvelope.iv && encrypted.iv && Buffer.compare(decodedEnvelope.iv, encrypted.iv) === 0).toBe(true);
            expect(Buffer.compare(decodedEnvelope.data, encrypted.data) === 0).toBe(true);
        });
    });
});
