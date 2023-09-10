import {
  MiddlewareConsumer,
  Module,
  NestModule,
  forwardRef,
} from '@nestjs/common';
import { AuthService } from './services/auth.service.js';
import { AuthController } from './controllers/auth.controller.js';
import { UsersModule } from '../users/users.module.js';
import { TokensModule } from '../tokens/tokens.module.js';
import { EmailModule } from '../mailer/email.module.js';
import { JwtToolsModule } from '../jwt/jwt-tools.module.js';
import { AuthAccessGuard } from './guards/auth-access.guard.js';
import { APP_GUARD } from '@nestjs/core';
import { RefreshTokenGuard } from './guards/refresh-token.guard.js';
import { RecoveryTokenGuard } from './guards/recovery-token.guard.js';
import { GoogleOAuthService } from './services/google-auth.service.js';
import { GoogleOAuthController } from './controllers/google-auth.controller.js';
import { GoogleStrategy } from './strategies/google.strategy.js';
import { GoogleOAuthGuard } from './guards/google-oauth.guard.js';
import { FingerprintsMiddleware } from './middlewares/fingerprints.middleware.js';
import { EncryptionModule } from '../encryption/encryption.module.js';

@Module({
  imports: [
    TokensModule,
    EmailModule,
    JwtToolsModule,
    EncryptionModule,
    forwardRef(() => UsersModule),
  ],
  controllers: [AuthController, GoogleOAuthController],
  providers: [
    {
      provide: APP_GUARD,
      useClass: AuthAccessGuard,
    },
    GoogleOAuthGuard,
    AuthService,
    GoogleStrategy,
    RefreshTokenGuard,
    RecoveryTokenGuard,
    GoogleOAuthService,
  ],
  exports: [AuthService],
})
export class AuthModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(FingerprintsMiddleware).forRoutes('*');
  }
}
