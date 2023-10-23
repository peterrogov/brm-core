import { Injectable } from '@nestjs/common';
import { SecretManager } from './secret-manager.interfaces';
import { randomBytes } from 'crypto';

@Injectable()
export class SecretManagerService implements SecretManager {
    private readonly store: Record<string, Buffer | string> = {
        "master-data-encryption-key": Buffer.from("6e02d424ec113ba54b2eeb5eb50f40a50212872cd7aaf4e5e5e104d64a7e612a", 'hex')
    };

    async getSecret(secretId: string): Promise<Buffer | null> {
        return this.store[secretId]
            ? Buffer.from(this.store[secretId])
            : null;
    }
}