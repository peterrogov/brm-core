import { ModuleRef } from '@nestjs/core';

export class ProviderWrapper {
  private static moduleRef: ModuleRef;

  static setModuleRef(moduleRef: ModuleRef) {
    this.moduleRef = moduleRef;
  }

  static get<T>(token: any): T {
    return this.moduleRef.get(token, { strict: false });
  }
}
