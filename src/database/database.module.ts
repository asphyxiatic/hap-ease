import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get<string>('database.url'),
        entities: [],
        migrations: ['dist/database/migrations/*.js'],
        migrationsTableName: 'migrations_table',
      }),
      inject: [ConfigService],
    }),
  ],
})
export class DatabaseModule {}
