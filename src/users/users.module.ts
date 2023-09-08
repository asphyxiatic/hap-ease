import { Module, forwardRef } from '@nestjs/common';
import { UsersService } from './services/users.service.js';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity.js';
import { UsersController } from './controllers/users.controller.js';
import { EmailModule } from '../mailer/email.module.js';
import { JwtToolsModule } from '../jwt/jwt-tools.module.js';
import { AuthModule } from '../auth/auth.module.js';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    EmailModule,
    JwtToolsModule,
    forwardRef(() => AuthModule),
  ],
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
