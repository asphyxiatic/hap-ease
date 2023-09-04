import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import config from './config/config.js';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({ forbidUnknownValues: false }));
  await app.listen(config.APP_PORT || 3000);
}
bootstrap();
