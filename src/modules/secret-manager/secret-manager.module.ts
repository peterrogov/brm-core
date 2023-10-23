import { Module } from '@nestjs/common';
import { SecretManagerService } from './secret-manager.service';
import { ModuleInjectables } from './secret-manager.constants';

@Module({
    imports: [],
    providers: [{
        provide: ModuleInjectables.InMemorySecretManager,
        useClass: SecretManagerService
    }],
    exports: [ModuleInjectables.InMemorySecretManager],
})
export class SecretManagerModule { }
