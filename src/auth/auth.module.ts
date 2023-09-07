import { Module, forwardRef } from '@nestjs/common';
import { AuthService } from './services/auth.service.js';
import { AuthController } from './controllers/auth.controller.js';
import { UsersModule } from '../users/user.module.js';
import { TokensModule } from '../tokens/token.module.js';
import { EmailModule } from '../mailer/email.module.js';
import { JwtToolsModule } from '../jwt/jwt-tools.module.js';
import { AuthAccessGuard } from './guards/auth-access.guard.js';
import { NotEmptyAuthorizationGuard } from './guards/not-empty-authorization.guard.js';

@Module({
  imports: [
    TokensModule,
    EmailModule,
    JwtToolsModule,
    forwardRef(() => UsersModule),
  ],
  controllers: [AuthController],
  providers: [AuthService, AuthAccessGuard, NotEmptyAuthorizationGuard],
  exports: [AuthAccessGuard, AuthService],
})
export class AuthModule {}
