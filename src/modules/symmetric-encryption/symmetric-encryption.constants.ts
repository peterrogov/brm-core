import { createHash } from "crypto";
import { SymmetricCipher } from "./symmetric-encryption.types";

/**
 * The default symmetric cipher used for encryption and decryption in the system.
 * 
 * Currently, AES-256-CBC (Advanced Encryption Standard with 256-bit key size in 
 * Cipher Block Chaining mode) is set as the default cipher. AES is widely recognized 
 * as the most secure symmetric encryption algorithm, while CBC is a commonly used 
 * mode of operation that allows the cipher to work effectively on longer sets of data.
 * 
 * Note: Be careful when changing the default cipher as it may impact all parts of the 
 * system that rely on this setting. If you need to switch to a different cipher, make 
 * sure to also manage the transition for any stored data that was encrypted using the 
 * previous cipher.
 * 
 * To learn more about different symmetric ciphers, you can visit:
 * - AES: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 * - CBC: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
 */
export const DEFAULT_SYMMETRIC_CIPHER = SymmetricCipher.AES256GCM;

/**
 * The number of rounds to be used by the bcrypt algorithm for generating the salt.
 * 
 * Bcrypt is a password-hashing algorithm that incorporates a salt to protect against 
 * rainbow table attacks. The number of rounds (also known as the cost factor) is a measure 
 * of computational complexity: the higher the number, the more iterations of the hashing 
 * algorithm are performed, and the longer it takes to generate the hash (and to crack it).
 * 
 * A value of 10 is generally considered a good balance between security and performance 
 * as of the current time (2023). However, as computational power increases, you may need 
 * to increase this value to maintain a high level of security.
 * 
 * Be aware that increasing the number of rounds will also increase the time it takes to 
 * hash a password, which can impact system performance and user experience.
 * 
 * To learn more about bcrypt and cost factors, you can visit:
 * - Bcrypt: https://en.wikipedia.org/wiki/Bcrypt
 * - Appropriate cost factor: https://security.stackexchange.com/questions/3959/recommended-of-rounds-for-bcrypt
 */
export const BCRYPT_SALT_ROUNDS = 10;

/**
 * The cryptographic hash function to be used by the PBKDF2 algorithm.
 * 
 * This constant should be set to a string corresponding to one of the 
 * cryptographic hash functions supported by Node.js' crypto module, 
 * such as 'sha256', 'sha512', etc. The choice of hash function can 
 * have significant impacts on the security and performance of the 
 * key derivation process.
 * 
 * For example, 'sha256' and 'sha512' are commonly recommended due to 
 * their balance of security and performance, while 'md5' is generally 
 * not recommended due to its known security vulnerabilities.
 * 
 * See the following resources for more information on choosing a suitable hash function:
 * - [Node.js crypto module documentation](https://nodejs.org/api/crypto.html#crypto_crypto_createhash_algorithm_options)
 * - [NIST Policy on Hash Functions](https://csrc.nist.gov/Projects/Hash-Functions/NIST-Policy-on-Hash-Functions)
 */
export const PBKF2_HASH_FUNCTION = 'sha256';

/**
 * The number of rounds to be used by the PBKDF2 algorithm.
 * 
 * The number of rounds determines how many times the hash function is 
 * applied during the generation of the derived key. A higher number of 
 * rounds means that the key derivation process takes longer, which can 
 * help to slow down an attacker trying to guess the password.
 * 
 * See the following resources for more information on choosing a suitable number of rounds:
 * - [NIST Special Publication 800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
 * - [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
 */
export const PBKF2_ROUNDS = 600000;

/**
 * The size (in bytes) of the salt to be used by the PBKDF2 algorithm.
 * 
 * The salt size is typically set to be the same size as the output 
 * digest of the chosen hash function for optimal security. In this case, 
 * it is computed based on the digest length of the hash function specified 
 * in the `PBKF2_HASH_FUNCTION` constant.
 * 
 * Salts are used to prevent pre-computation attacks (like rainbow tables) 
 * and to ensure that each derived key is unique even if the input password 
 * is the same. Having a salt with the same length as the hash output can 
 * ensure a high degree of randomness and uniqueness.
 * 
 * Note, when the hash function is changed, the salt size will 
 * adjust accordingly based on the digest length of the new hash function.
 */
export const PBKF2_SALT_SIZE = createHash(PBKF2_HASH_FUNCTION).digest().length;

/**
 * A separator string/characted used to join several parts on an envelope
 * string representation together. Be careful when changing this constant
 * because any envelopes encoded with the old value will not be able to
 * decode any longer. 
 */
export const ENVELOPE_SEPARATOR = ":";