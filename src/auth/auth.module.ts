import { Module } from '@nestjs/common';
import { AuthService } from './services/auth.service.js';
import { AuthController } from './controllers/auth.controller.js';

@Module({
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
