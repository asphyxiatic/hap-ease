import { Module } from '@nestjs/common';
import { EncryptionService } from './services/encryption.service.js';

@Module({
  providers: [EncryptionService],
  exports: [EncryptionService],
})
export class EncryptionModule {}
