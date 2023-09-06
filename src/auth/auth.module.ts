import { Module } from '@nestjs/common';
import { AuthService } from './services/auth.service.js';
import { AuthController } from './controllers/auth.controller.js';
import { JwtModule } from '@nestjs/jwt';
import { UsersModule } from '../users/user.module.js';
import { TokensModule } from '../tokens/token.module.js';
import { EmailModule } from '../mailer/email.module.js';
import { JwtToolsModule } from '../jwt/jwt-tools.module.js';

@Module({
  imports: [UsersModule, TokensModule, EmailModule, JwtToolsModule],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
