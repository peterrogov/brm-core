import { Injectable } from '@nestjs/common';
import { randomBytes } from 'crypto';
import { EncryptedDocumentService } from './modules/encrypted-document/encrypted-document.service';

@Injectable()
export class AppService {
  constructor(private encryptedDocumentService: EncryptedDocumentService) { }

  async getHello(take?: number, after?: number, query?: string): Promise<any> {
    // This is just an example. Replace with your actual document data.
    const documentData = {
      firstName: randomBytes(8).toString("hex"),
      lastName: randomBytes(8).toString("hex"),
      dateOfBirth: "1990-01-01",
      sex: "M"
    };

    // return this.encryptedDocumentService.create("person", documentData);
    const documents = [];
    for await (const document of this.encryptedDocumentService.scan({
      recordFilter: { type: "person" },
      after,
      take,
      documentFilter: query
    })) {
      documents.push(document);
    }

    return documents;
  }
}
