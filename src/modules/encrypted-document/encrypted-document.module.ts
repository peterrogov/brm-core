import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataEncryptionModule } from '../data-encryption/data-encryption.module';
import { EncryptedDocument } from './encrypted-document.entity';
import { EncryptedDocumentService } from './encrypted-document.service';
import { DocumentQueryModule } from '../document-query/document-query.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([EncryptedDocument]),
    DataEncryptionModule,  
    DocumentQueryModule  
  ],
  providers: [EncryptedDocumentService],
  exports: [EncryptedDocumentService],
})
export class EncryptedDocumentModule { }
