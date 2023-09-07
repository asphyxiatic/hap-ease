import { Module } from '@nestjs/common';
import { TokensService } from './services/tokens.service.js';
import { Token } from './entities/token.entity.js';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [TypeOrmModule.forFeature([Token])],
  providers: [TokensService],
  exports: [TokensService],
})
export class TokensModule {}
