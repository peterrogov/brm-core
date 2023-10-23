import { ModuleError } from "../../core/errors";

const MODULE_NAME = "DocumentQuery";

export class DocumentQueryError extends ModuleError {
    constructor(message: string) {
        super(MODULE_NAME, message);
    }
}

