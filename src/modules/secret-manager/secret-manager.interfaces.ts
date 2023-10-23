export interface SecretManager {
    getSecret: (secretName: string) => Promise<Buffer | null>;
}