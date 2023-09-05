import { Body, Controller, Post, Request } from '@nestjs/common';
import { AuthService } from '../services/auth.service.js';
import { SignUpDto } from '../dto/sign-up.dto.js';
import { SignInDto } from '../dto/sign-in.dto.js';
import { SignUpResponseDto } from '../dto/sign-up-response.dto.js';
import { SignInResponseDto } from '../dto/sign-in-response.dto.js';
import { UpdateTokensDto } from '../dto/update-token.dto.js';
import { Request as Req } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('sign-up')
  async signUp(@Body() credentials: SignUpDto): Promise<SignUpResponseDto> {
    return this.authService.signUp(credentials);
  }

  @Post('sign-in')
  async signIn(@Body() credentials: SignInDto): Promise<SignInResponseDto> {
    return this.authService.signIn(credentials);
  }

  @Post('update-tokens')
  async updateTokens(@Request() request: Req): Promise<UpdateTokensDto> {
    // Временное решение
    const refreshToken = request.headers.authorization?.split(' ')[1];

    return this.authService.updateTokens(refreshToken!);
  }
}
