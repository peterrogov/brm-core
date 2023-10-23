import { Inject, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { AppInjectable } from 'src/shared/injectables';
import { Between, Repository } from 'typeorm';
import { SecretManager } from '../secret-manager/secret-manager.interfaces';
import { SymmetricEncryptionService } from '../symmetric-encryption/symmetric-encryption.service';
import { DataEncryptionKey } from './data-encryption-key.entity';

@Injectable()
export class DataEncryptionService {
    constructor(
        @Inject(SymmetricEncryptionService)
        private encryptionService: SymmetricEncryptionService,
        @Inject(AppInjectable.SecretManager.InMemorySecretManager)
        private secretManagerService: SecretManager,
        @InjectRepository(DataEncryptionKey)
        private dataEncryptionKeyRepository: Repository<DataEncryptionKey>,
    ) { }

    private async getDataEncryptionKey(): Promise<DataEncryptionKey> {
        const startOfDay = new Date();
        startOfDay.setHours(0, 0, 0, 0);

        const endOfDay = new Date();
        endOfDay.setHours(23, 59, 59, 999);

        let encryptionKey = await this.dataEncryptionKeyRepository.findOne({
            where: {
                enabled: true,
                createdAt: Between(startOfDay, endOfDay)
            },
            select: ['id', 'keyEnvelope'],
        });

        return encryptionKey || this.createNewKey();
    }

    async encryptValue(plainValue: Buffer): Promise<[number, Buffer]> {
        const encryptionKey = await this.getDataEncryptionKey();
        const masterKey = await this.getMasterKey();
        const encryptedDEK = this.encryptionService.decodeEnvelope(encryptionKey.keyEnvelope);
        const dek = this.encryptionService.decrypt(masterKey, encryptedDEK);

        // Encrypt the plain value with the DEK
        const encryptedEnvelope = this.encryptionService.encrypt({ key: dek, data: plainValue });
        const encodedEnvelope = this.encryptionService.encodeEnvelope(encryptedEnvelope);
        return [encryptionKey.id, encodedEnvelope];
    }

    private async findDek(dekId: number): Promise<Buffer> {
        const encryptionKey = await this.dataEncryptionKeyRepository.findOne({
            where: { id: dekId },
            select: ['keyEnvelope'],
        });

        if (!encryptionKey) {
            throw new Error("Given encryption key does not exist!");
        }

        return encryptionKey.keyEnvelope;
    }

    async decryptValue(dekId: number, envelope: Buffer): Promise<Buffer> {
        const encryptedValue = this.encryptionService.decodeEnvelope(envelope);
        const masterKey = await this.getMasterKey();
        const encryptionKey = await this.findDek(dekId);
        const encryptedDEK = this.encryptionService.decodeEnvelope(encryptionKey);
        const dek = this.encryptionService.decrypt(masterKey, encryptedDEK);
        return this.encryptionService.decrypt(dek, encryptedValue);
    }

    private async createNewKey(): Promise<DataEncryptionKey> {
        const masterKey = await this.getMasterKey();
        // Generate a new DEK and encrypt
        const dek = this.encryptionService.generateKey();
        const encryptedDEK = this.encryptionService.encrypt({ key: masterKey, data: dek });
        const encodedDEK = this.encryptionService.encodeEnvelope(encryptedDEK);

        const entry = this.dataEncryptionKeyRepository.create({
            enabled: true,
            keyEnvelope: encodedDEK
        });

        return this.dataEncryptionKeyRepository.save(entry);
    }

    private readonly keyName = "master-data-encryption-key";
    private async getMasterKey(): Promise<Buffer> {
        const rawMasterKey = await this.secretManagerService.getSecret(this.keyName);
        if (!rawMasterKey) {
            throw new Error("Invalid master key");
        }

        return Buffer.from(rawMasterKey);
    }
}
