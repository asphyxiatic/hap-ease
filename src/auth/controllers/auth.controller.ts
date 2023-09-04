import { Controller, Post } from '@nestjs/common';
import { AuthService } from '../services/auth.service.js';
import { User } from '../../users/entities/user.entity.js';
import { SignUpDto } from '../dto/sign-up.dto.js';
import { SignInDto } from '../dto/sign-in.dto.js';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('sign-up')
  async signUp(credentials: SignUpDto): Promise<any> {
    return this.authService.signUp(credentials);
  }

  @Post('sign-in')
  async signIn(credentials: SignInDto): Promise<User> {
    return this.authService.signIn(credentials);
  }
}
