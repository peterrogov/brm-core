import { ModuleInjectables as SecretManager } from "../modules/secret-manager/secret-manager.constants";

export const AppInjectable = {
    SecretManager
} as const;

export function validateInjectables() {
    const injectableValues: string[] = [];
    const moduleKeys = Object.keys(AppInjectable) as (keyof typeof AppInjectable)[];;
    for (const module of moduleKeys) {
        const serviceKeys = Object.values(AppInjectable[module]);
        for (const service of serviceKeys) {
            const serviceFull = `${module}:${service}`;
            if (injectableValues.includes(serviceFull)) {
                throw new Error(`Duplicate injectable: ${serviceFull}`);
            } else {
                injectableValues.push(serviceFull);
            }
        }
    }
}

AppInjectable.SecretManager.InMemorySecretManager