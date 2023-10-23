export class ModuleError extends Error {
    readonly moduleName: string;

    constructor(moduleName: string, message: string) {
        super(message);
        this.moduleName = moduleName;
    }

}