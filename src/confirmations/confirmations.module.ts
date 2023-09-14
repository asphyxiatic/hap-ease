import { Module } from '@nestjs/common';
import { ConfirmationsEmailService } from './services/confirmations-email.service.js';
import { UsersModule } from '../users/users.module.js';
import { JwtToolsModule } from '../jwt/jwt-tools.module.js';
import { EncryptionModule } from '../encryption/encryption.module.js';
import { ConfirmationsEmailController } from './controllers/confirmations-email.controller.js';
import { AuthModule } from '../auth/auth.module.js';
import { ConfirmationTokenGuard } from './guards/confirmation-token.guard.js';

@Module({
  imports: [UsersModule, JwtToolsModule, EncryptionModule, AuthModule],
  controllers: [ConfirmationsEmailController],
  providers: [ConfirmationsEmailService, ConfirmationTokenGuard],
})
export class ConfirmationsModule {}
