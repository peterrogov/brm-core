import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SecretManagerModule } from '../secret-manager/secret-manager.module';
import { SymmetricEncryptionModule } from '../symmetric-encryption/symmetric-encryption.module';
import { DataEncryptionKey } from './data-encryption-key.entity';
import { DataEncryptionService } from './data-encryption.service';

@Module({
    imports: [
        TypeOrmModule.forFeature([DataEncryptionKey]),
        SymmetricEncryptionModule,
        SecretManagerModule
    ],
    providers: [
        DataEncryptionService
    ],
    exports: [DataEncryptionService],
})
export class DataEncryptionModule { }
