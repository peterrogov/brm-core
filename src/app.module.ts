import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DataEncryptionKey } from './modules/data-encryption/data-encryption-key.entity';
import { EncryptedDocument } from './modules/encrypted-document/encrypted-document.entity';
import { EncryptedDocumentModule } from './modules/encrypted-document/encrypted-document.module';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'localhost',
      port: 55355,
      username: 'postgres',
      password: 'password',
      database: 'humanitech-brm',
      entities: [
        DataEncryptionKey,
        EncryptedDocument
      ],
      synchronize: true,
    }),
    EncryptedDocumentModule
  ],
  controllers: [AppController],
  providers: [
    AppService
  ],
})
export class AppModule { }
