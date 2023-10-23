import { Controller, Get, Param, Post } from '@nestjs/common';
import { EncryptedDocumentService } from './encrypted-document.service';

@Controller('documents')
export class EncryptedDocumentController {
  constructor(private readonly encryptedDocumentService: EncryptedDocumentService) { }

  @Get(':documentId/:versionId?')
  async getSingle(
    @Param('documentId') documentId: string,
    @Param('versionId') versionId?: string
  ): Promise<any[]> {
    return [];
  }

  @Post()
  async create() {

  }

  
}
