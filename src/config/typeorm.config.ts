import { Injectable } from '@nestjs/common';
import { TypeOrmModuleOptions, TypeOrmOptionsFactory } from '@nestjs/typeorm';
import { appDataSource } from '../database/index.js';

@Injectable()
export class TypeOrmConfigService implements TypeOrmOptionsFactory {

  createTypeOrmOptions(): TypeOrmModuleOptions {
    return {
      ...appDataSource.options,
    };
  }
}
