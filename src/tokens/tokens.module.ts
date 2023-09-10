import { Module } from '@nestjs/common';
import { TokensService } from './services/tokens.service.js';
import { Token } from './entities/token.entity.js';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EncryptionModule } from '../encryption/encryption.module.js';

@Module({
  imports: [TypeOrmModule.forFeature([Token]), EncryptionModule],
  providers: [TokensService],
  exports: [TokensService],
})
export class TokensModule {}
