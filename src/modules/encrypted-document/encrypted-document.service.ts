import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DataEncryptionService } from '../data-encryption/data-encryption.service';
import { EncryptedDocument } from './encrypted-document.entity';
import { DecryptedDocument, Payload, ScanOptions } from './encrypted-document.types';
import { DocumentQueryService } from '../document-query/document-query.service';

@Injectable()
export class EncryptedDocumentService {
    constructor(
        @InjectRepository(EncryptedDocument)
        private documents: Repository<EncryptedDocument>,
        private dataEncryptionService: DataEncryptionService,
        private documentQueryService: DocumentQueryService,
    ) { }


    serializePayload<T = unknown>(payload: Payload<T>): Buffer {
        const json = JSON.stringify(payload);
        return Buffer.from(json);
    }

    async create<T = unknown>(type: string, payload: Payload<T>): Promise<EncryptedDocument> {
        const document = new EncryptedDocument();
        document.type = type;
        document.createdAt = new Date();
        document.isCurrent = true;
        const serializedPayload = this.serializePayload(payload);
        const [dekId, envelope] = await this.dataEncryptionService.encryptValue(serializedPayload);
        document.payload = envelope;
        document.dekId = dekId;

        return this.documents.save(document);
    }

    async *scan(options: ScanOptions): AsyncGenerator<DecryptedDocument> {
        let skipCount = options.after ?? 0;
        const batchSize = typeof options.take === "number"
            ? Math.min(100, options.take)
            : 100;

        let taken = 0;
        while (true) {
            const records = await this.documents.find({
                where: options.recordFilter,
                order: { id: "ASC" },
                skip: skipCount,
                take: batchSize
            });

            // No more records in the database
            if (records.length === 0) {
                return;
            }

            skipCount += records.length;

            for (const record of records) {
                const decryptedPayload = await this.dataEncryptionService.decryptValue(record.dekId, record.payload);
                const payload = JSON.parse(decryptedPayload.toString());
                // ... schema validate

                if (options.documentFilter &&
                    !this.documentQueryService.matchesQuery(payload, options.documentFilter)
                ) {
                    continue;
                }

                const { dekId, ...meta } = record;
                const document: DecryptedDocument = {
                    ...meta,
                    payload
                }

                yield document;

                taken++;
                if (options.take && taken >= options.take) {
                    return;
                }
            }
        }
    }

    async getAll(): Promise<any> {
        const allDocuments = await this.documents.find();
        const result: (Omit<EncryptedDocument, "payload"> & { payload: Payload })[] = [];
        let decryptTime = 0;
        for (const doc of allDocuments) {
            let t = process.hrtime.bigint();
            const payloadBuffer = await this.dataEncryptionService.decryptValue(doc.dekId, doc.payload);
            t = process.hrtime.bigint() - t;
            decryptTime += Number(t) / 1000000;
            const payload = JSON.parse(payloadBuffer.toString());
            result.push({
                ...doc,
                payload
            });
        }

        return {
            decryptTime,
            data: result
        };
    }
}
