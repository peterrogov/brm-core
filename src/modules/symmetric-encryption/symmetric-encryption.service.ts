import { Injectable } from '@nestjs/common';
import { compareSync, hashSync } from 'bcrypt';
import { CipherGCM, CipherGCMTypes, DecipherGCM, createCipheriv, createDecipheriv, getCipherInfo, pbkdf2Sync, randomBytes } from 'crypto';
import { BCRYPT_SALT_ROUNDS, DEFAULT_SYMMETRIC_CIPHER, PBKF2_HASH_FUNCTION, PBKF2_ROUNDS, PBKF2_SALT_SIZE } from './symmetric-encryption.constants';
import { UnsupportedCipherError } from './symmetric-encryption.errors';
import { EncryptInput, EncryptOutput, Envelope, SymmetricCipher, SymmetricCipherName } from './symmetric-encryption.types';

/**
 * Provides utility methods for symmetric encryption and decryption operations.
 * This includes methods for encrypting/decrypting Buffers, handling encrypted
 * envelopes (which bundle together encrypted data and their associated IVs and
 * cipher types), encoding/decoding envelopes to/from strings, secure hashing, 
 * and key/IV generation.
 */
@Injectable()
export class SymmetricEncryptionService {
    private getCipherName(cipher: SymmetricCipher): string {
        if (cipher < 0 || cipher >= SymmetricCipherName.length) {
            return "";
        }

        return SymmetricCipherName[cipher];
    }

    isGCMCipher(cipherName: string): cipherName is CipherGCMTypes {
        return cipherName.endsWith('-gcm')
    }

    private getEncryptionIV(cipher: SymmetricCipher, iv?: Buffer | null): Buffer | null {
        const encryptionIV = iv ?? this.getIV(cipher);
        this.validateIV(cipher, encryptionIV);
        return encryptionIV;
    }

    /**
     * Encrypts a given data Buffer using the provided symmetric key and
     * initialization vector (IV) using a specified cipher. If no IV is
     * provided, one is generated using the specified cipher.
     * 
     * @param key    The symmetric key to be used for decryption.
     * 
     * @param data   The data Buffer to be encrypted.
     * 
     * @param iv     The initialization vector (IV) to be used for
     *               decryption. If not provided, null is used.
     * 
     * @param cipher The cipher algorithm to be used for encryption.
     *               Defaults to `DEFAULT_SYMMETRIC_CIPHER`
     * 
     * @returns      The encrypted data as a Buffer.
     * 
     * @throws       Throws an error if encryption fails.
     */
    encrypt(input: EncryptInput): EncryptOutput {
        const cipher = input.cipher ?? DEFAULT_SYMMETRIC_CIPHER;
        const cipherName = this.getCipherName(cipher);

        if (this.isGCMCipher(cipherName) && Buffer.isBuffer(input.iv)) {
            throw new Error("In GCM mode, do not manually set the IV. A fresh and unique random IV will be generated automatically for each encryption operation.");
        }

        const iv = this.getEncryptionIV(cipher, input.iv);
        const encrypter = createCipheriv(cipherName, input.key, iv);
        const encryptedData = Buffer.concat([
            encrypter.update(input.data),
            encrypter.final()
        ]);

        const output: EncryptOutput = {
            cipher,
            data: encryptedData,
            iv
        }

        if (this.isGCMCipher(cipherName)) {
            output.authTag = (encrypter as CipherGCM).getAuthTag();
        }

        return output;
    }

    /**
     * Decrypts a given encrypted data Buffer using the provided symmetric key and 
     * optionally an initialization vector (IV) using a specified cipher.
     * 
     * @param key    The symmetric key to be used for decryption.
     * 
     * @param data   The encrypted data Buffer to be decrypted.
     * 
     * @param iv     The initialization vector (IV) to be used for
     *               decryption. If not provided, null is used.
     * 
     * @param cipher The cipher algorithm to be used for encryption.
     *               Defaults to `DEFAULT_SYMMETRIC_CIPHER`
     * 
     * @returns      The decrypted data as a Buffer.
     * 
     * @throws       Throws an error if decryption fails.
     */
    decrypt(key: Buffer, encrypted: EncryptOutput): Buffer {
        this.validateIV(encrypted.cipher, encrypted.iv);
        const cipherName = this.getCipherName(encrypted.cipher);
        const encrypter = createDecipheriv(cipherName, key, encrypted.iv);
        if (this.isGCMCipher(cipherName)) {
            if (!Buffer.isBuffer(encrypted.authTag) || encrypted.authTag.length === 0) {
                throw new Error("Decryption requires auth tag");
            } else {
                (encrypter as DecipherGCM).setAuthTag(encrypted.authTag);
            }
        }

        return Buffer.concat([
            encrypter.update(encrypted.data),
            encrypter.final()
        ]);
    }

    /**
     * Validates if a given Initialization Vector (IV) is valid for a specified symmetric cipher.
     *
     * The method first retrieves information about the given cipher (like its required IV length),
     * and then checks the provided IV against these requirements. If the cipher requires an IV, 
     * the method checks that the provided IV is a buffer and that its length matches the required 
     * length. If the cipher does not require an IV, the method checks that the provided IV is null.
     *
     * @param cipher The symmetric cipher for which the IV is being validated.
     *               The function `getCipherInfo` should be able to provide
     *               information about this cipher, like its required IV length.
     * 
     * @param iv     The Initialization Vector (IV) to be validated. Should be a buffer 
     *               of the correct length if the cipher requires an IV, or null if it 
     *               does not.
     *
     * @returns      Returns `true` if the provided IV is valid for the given cipher, and 
     *                 `false` otherwise.
     */
    private validateIV(cipher: SymmetricCipher, iv: Buffer | null) {
        const cipherInfo = getCipherInfo(this.getCipherName(cipher));
        const isValid = cipherInfo?.ivLength
            ? Buffer.isBuffer(iv) && iv.length === cipherInfo.ivLength
            : iv === null;

        if (!isValid) {
            throw new Error("Invalid IV provided for selected cipher");
        }
    }

    /**
     * Encodes an EncryptedEnvelope into a string representation.
     * 
     * @param envelope The envelope to be encoded.
     * 
     * @returns        The string representation of the envelope.
     */
    encodeEnvelope(envelope: EncryptOutput): Buffer {
        const message = new Envelope({
            cipher: envelope.cipher,
            data: envelope.data,
            iv: Buffer.isBuffer(envelope.iv) ? envelope.iv : undefined,
            authTag: Buffer.isBuffer(envelope.authTag) ? envelope.authTag : undefined
        });

        return Buffer.from(Envelope.encode(message).finish());
    }

    /**
     * Decodes a string into an EncryptedEnvelope.
     * 
     * @param encodedEnvelope The string representation of the envelope.
     * 
     * @returns               The decoded envelope.
     */
    decodeEnvelope(envelope: Buffer): EncryptOutput {
        const { cipher, iv, authTag, data } = Envelope.decode(envelope);
        return {
            cipher,
            data,
            iv: iv ?? null,
            authTag
        };
    }

    /**
     * Creates a secure hash of a given Buffer using bcrypt.
     * 
     * @param value The Buffer to be hashed.
     * 
     * @returns     The resulting hash as a string.
     * 
     * @throws      Throws an error if a non-empty Buffer is not provided.
     */
    secureHash(value: Buffer): string {
        // const isBuffer = NodeBuffer.isBuffer(NodeBuffer.from(value));
        if (!Buffer.isBuffer(value) || value.length === 0) {
            throw new Error("Non-empty buffer is expected");
        }

        return hashSync(value, BCRYPT_SALT_ROUNDS);
    }

    /**
     * Validate a hash for given input data using bcrypt's compareSync method.
     * This method performs a synchronous password-hash comparison.
     *
     * @param input The input data to be validated. This should be a buffer 
     *              containing the original data (often a password) that was 
     *              hashed.
     * 
     * @param hash  The hashed string against which the input is compared. 
     *              This should be a hash generated from the original data.
     *
     * @returns     Returns 'true' if the input matches the hash (i.e., if the 
     *              input, when hashed, generates the provided hash). Otherwise, 
     *              it returns 'false'.
     */
    validateHash(input: Buffer, hash: string): boolean {
        return compareSync(input, hash)
    }

    /**
     * Derives a strong encryption key from the input key and a salt using the PBKDF2 algorithm.
     * 
     * @param key    The input key to be buffered
     * @param salt   The salt. If provided, the salt length must be exactly PBKF2_SALT_SIZE
     *               bytes long. If not provided,an empty Buffer is used.
     * 
     * @returns The derived buffered key
     * 
     * @throws  Throws an error if the salt length is not PBKF2_SALT_SIZE.
     */
    getBufferedKey(key: string | Buffer, salt: string | Buffer = Buffer.alloc(0)): Buffer {
        const saltBuffer = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, "ascii");

        if (saltBuffer.length !== 0 && saltBuffer.length !== PBKF2_SALT_SIZE) {
            throw new Error(`Salt must be exactly ${PBKF2_SALT_SIZE} bytes`);
        }

        return pbkdf2Sync(
            key,
            saltBuffer,
            PBKF2_ROUNDS,
            PBKF2_SALT_SIZE,
            PBKF2_HASH_FUNCTION
        );
    }

    /**
     * Generates a random cryptographically strong buffer of the specified length
     * 
     * @param length The length of the buffer in bytes
     * 
     * @returns      The random buffer
     */
    private getRandomBuffer(length: number): Buffer {
        return randomBytes(length);
    }

    /**
     * Generates a random cryptographically strong encryption key for a specified cipher.
     *
     * @param cipher The symmetric cipher to be used.
     * 
     * @param type   Specifies the purpose of the random buffer. With 'key'
     *               provided as type, the function will return a Buffer, 
     *               which is generated based on the key length required
     *               by the cipher.
     * 
     * @returns      The generated encryption key as a Buffer.
     * 
     * @throws       Throws an error if the symmetric cipher is not supported.
     */
    private getCipherRandomBuffer(cipher: SymmetricCipher, type: "key"): Buffer;
    /**
     * Generates a random cryptographically strong initialization vector (IV)
     * buffer for a specified symmetric cipher.
     *
     * @param cipher The symmetric cipher to be used.
     * 
     * @param type   Specifies the purpose of the random buffer. With `iv` provided
     *               as type, the function will return a `Buffer | null`, depending
     *               on whether the cipher requires an initialization vector (IV).
     *               If IV is required, a Buffer is generated based on the IV length
     *               required by the cipher.
     * 
     * @returns      The generated initialization vector (IV) as a Buffer or null.
     * 
     * @throws       Throws an error if the symmetric cipher is not supported.
     */
    private getCipherRandomBuffer(cipher: SymmetricCipher, type: "iv"): Buffer | null;
    /**
     * Generates a cryptographically strong random buffer of appropriate size for
     * either the key or initialization vector (IV) for a specified symmetric cipher.
     *
     * @param cipher The symmetric cipher to be used.
     * 
     * @param type   Specifies the purpose of the random buffer. If 'key' is provided
     *               as type, a buffer for an encryption key is generated. If 'iv' is
     *               provided as type, a buffer for an initialization vector (IV) is
     *               generated if the cipher requires it.
     * 
     * @returns      The generated buffer. Returns null if the type is 'iv' and the
     *               cipher does not require an IV.
     * 
     * @throws       Throws an error if the symmetric cipher is not supported.
     */
    private getCipherRandomBuffer(cipher: SymmetricCipher, type: "iv" | "key"): Buffer | null {
        const cipherName = this.getCipherName(cipher);
        const cipherInfo = getCipherInfo(cipherName);
        if (!cipherInfo) {
            throw new UnsupportedCipherError(cipherName);
        }

        if (type === "iv") {
            return cipherInfo.ivLength ? this.getRandomBuffer(cipherInfo.ivLength) : null;
        } else {
            return this.getRandomBuffer(cipherInfo.keyLength);
        }
    }

    /**
     * Generates a cryptographically strong random key based on the symmetric cipher
     * provided as an argument. The key length depends on the cipher algorithm used.
     *
     * @param cipher The symmetric cipher to be used for generating the key.
     * 
     * @returns      The generated cryptographically strong random encryption key
     *               as a Buffer.
     * 
     * @throws       Throws an error if the symmetric cipher is not supported.
     */
    // generateKey(cipher: SymmetricCipher): Buffer
    /**
     * Generates a cryptographically strong random key of a specified length. 
     * The length of the key is determined by the number provided as an argument.
     *
     * @param length The length of the key to be generated.
     * 
     * @returns      The generated cryptographically strong random encryption key
     *               as a Buffer.
     * 
     * @throws       Throws an error if the symmetric cipher is not supported.
     */
    // generateKey(length: number): Buffer
    /**
     * Generates a cryptographically strong random key based on either a symmetric
     * cipher or a specified key length. When a symmetric cipher is provided, the
     * key length is determined by the cipher algorithm. When a number is provided,
     * a key of that length is generated.     
     * 
     * @param input A symmetric cipher or a number representing the key length.
     * 
     * @returns     The generated cryptographically strong random encryption key
     *              as a Buffer.
     *
     * @throws      Throws an error if the symmetric cipher is not supported.
     */
    generateKey(input: SymmetricCipher = DEFAULT_SYMMETRIC_CIPHER): Buffer {
        return this.getCipherRandomBuffer(input, "key");
    }

    /**
     * Generates a cryptographically strong random initialization vector (IV)
     * based on the symmetric cipher provided as an argument. The IV length is
     * determined by the cipher algorithm used. If the cipher does not require
     * an IV, this function returns null.
     *
     * @param cipher The symmetric cipher to be used for generating the IV. 
     *               Default is `DEFAULT_SYMMETRIC_CIPHER`
     * 
     * @returns      The generated IV as a Buffer. If the cipher does not require
     *               an IV, null is returned.
     * 
     * @throws       Throws an error if the symmetric cipher is not supported.
     */
    getIV(cipher: SymmetricCipher = DEFAULT_SYMMETRIC_CIPHER): Buffer | null {
        return this.getCipherRandomBuffer(cipher, "iv");
    }
}