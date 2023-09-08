import { Module, forwardRef } from '@nestjs/common';
import { AuthService } from './services/auth.service.js';
import { AuthController } from './controllers/auth.controller.js';
import { UsersModule } from '../users/users.module.js';
import { TokensModule } from '../tokens/tokens.module.js';
import { EmailModule } from '../mailer/email.module.js';
import { JwtToolsModule } from '../jwt/jwt-tools.module.js';
import { AuthAccessGuard } from './guards/auth-access.guard.js';
import { APP_GUARD } from '@nestjs/core';
import { RefreshTokenGuard } from './guards/refresh-token.guard.js';

@Module({
  imports: [TokensModule, EmailModule, JwtToolsModule, UsersModule],
  controllers: [AuthController],
  providers: [
    {
      provide: APP_GUARD,
      useClass: AuthAccessGuard,
    },
    AuthService,
    RefreshTokenGuard,
  ],
  exports: [AuthService],
})
export class AuthModule {}
