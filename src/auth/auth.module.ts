import { Module } from '@nestjs/common';
import { AuthService } from './services/auth.service.js';
import { AuthController } from './controllers/auth.controller.js';
import { JwtModule } from '@nestjs/jwt';
import { UsersModule } from '../users/user.module.js';
import { TokensModule } from '../tokens/token.module.js';

@Module({
  imports: [JwtModule.register({}), UsersModule, TokensModule],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
