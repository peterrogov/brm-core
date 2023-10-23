import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ProviderWrapper } from './core/ProviderWrapper';
import { ModuleRef } from '@nestjs/core';
import { validateInjectables } from './shared/injectables';
import cluster from 'node:cluster';
import { availableParallelism } from 'node:os';

const numCPUs = availableParallelism();

if (cluster.isPrimary) {
  // Fork workers for each CPU core
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died`);
    // If you want, you can create a new worker when one dies:
    // cluster.fork();
  });
} else {
  async function bootstrap() {
    validateInjectables();
    const app = await NestFactory.create(AppModule);
    ProviderWrapper.setModuleRef(app.get(ModuleRef));
    await app.listen(3000);
  }

  bootstrap();
}
