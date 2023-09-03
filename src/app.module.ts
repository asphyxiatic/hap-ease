import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import configuration from './config/configuration.js';
import { DatabaseModule } from './database/database.module.js';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [configuration],
      validationOptions:{
        allowUnknown: false,
        abortEarly: false,
      }
    }),
    DatabaseModule,
  ],
})
export class AppModule {}
