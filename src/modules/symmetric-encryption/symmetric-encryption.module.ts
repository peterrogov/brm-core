import { Module } from '@nestjs/common';
import { SymmetricEncryptionService } from './symmetric-encryption.service';

@Module({
    imports: [],
    providers: [SymmetricEncryptionService],
    exports: [SymmetricEncryptionService],
})
export class SymmetricEncryptionModule { }
