import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { accessLog } from './common/access-log.middleware';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(accessLog(process.env.SERVICE_NAME ?? 'unknown'));
  await app.listen(3000, '0.0.0.0');
}
bootstrap();
