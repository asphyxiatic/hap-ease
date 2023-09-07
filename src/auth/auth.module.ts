import { Module, forwardRef } from '@nestjs/common';
import { AuthService } from './services/auth.service.js';
import { AuthController } from './controllers/auth.controller.js';
import { UsersModule } from '../users/users.module.js';
import { TokensModule } from '../tokens/tokens.module.js';
import { EmailModule } from '../mailer/email.module.js';
import { JwtToolsModule } from '../jwt/jwt-tools.module.js';
import { AuthAccessGuard } from './guards/auth-access.guard.js';
import { NotEmptyAuthorizationGuard } from './guards/not-empty-authorization.guard.js';
import { GoogleAuthService } from './services/google-auth.service.js';

@Module({
  imports: [
    TokensModule,
    EmailModule,
    JwtToolsModule,
    forwardRef(() => UsersModule),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    GoogleAuthService,
    AuthAccessGuard,
    NotEmptyAuthorizationGuard,
  ],
  exports: [AuthAccessGuard, AuthService],
})
export class AuthModule {}
