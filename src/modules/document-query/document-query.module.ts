import { Module } from '@nestjs/common';
import { DocumentQueryService } from './document-query.service';

@Module({
    imports: [],
    providers: [DocumentQueryService],
    exports: [DocumentQueryService],
})
export class DocumentQueryModule { }
