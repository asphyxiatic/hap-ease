import { Module } from '@nestjs/common';
import { AuthService } from './services/auth.service.js';
import { AuthController } from './controllers/auth.controller.js';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../users/entities/user.entity.js';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
