import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import config from './config/config.js';
import * as session from 'express-session';
import * as passport from 'passport';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(
    session({
      secret: config.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: 60000,
      },
    }),
  );
  app.use(passport.initialize());
  app.use(passport.session());

  app.useGlobalPipes(new ValidationPipe({ forbidUnknownValues: false }));

  await app.listen(config.APP_PORT || 3000);
}
bootstrap();
