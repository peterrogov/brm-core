import { ModuleError } from "../../core/errors";
//import { SymmetricEncryptionModule } from "./symmetric-encryption.module";

const MODULE_NAME = "SymmetricEncryption";

export class SymmetricEncryptionError extends ModuleError {
    constructor(message: string) {
        super(MODULE_NAME, message);
    }
}

export class UnsupportedCipherError extends SymmetricEncryptionError {
    constructor(cipherName: string) {
        super(`Unsupported cipher: ${cipherName}`);
    }
}