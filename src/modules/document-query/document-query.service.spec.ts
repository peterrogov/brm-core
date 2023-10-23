import { Test, TestingModule } from '@nestjs/testing';
import { DocumentQueryService } from './document-query.service';


describe('DocumentQueryService', () => {
    let service: DocumentQueryService;

    beforeEach(async () => {
        const app: TestingModule = await Test.createTestingModule({
            providers: [DocumentQueryService],
        }).compile();

        service = app.get<DocumentQueryService>(DocumentQueryService);
    });


});
