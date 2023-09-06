import { Module } from '@nestjs/common';
import { UsersService } from './services/user.service.js';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity.js';
import { UserController } from './controllers/user.controller.js';
import { EmailModule } from '../mailer/email.module.js';
import { JwtToolsModule } from '../jwt/jwt-tools.module.js';

@Module({
  imports: [TypeOrmModule.forFeature([User]), EmailModule, JwtToolsModule],
  controllers: [UserController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
