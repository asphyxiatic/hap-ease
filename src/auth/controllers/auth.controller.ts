import {
  Body,
  Controller,
  Delete,
  Patch,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from '../services/auth.service.js';
import { SignUpDto } from '../dto/sign-up.dto.js';
import { SignInDto } from '../dto/sign-in.dto.js';
import { SignUpResponseDto } from '../dto/sign-up-response.dto.js';
import { SignInResponseDto } from '../dto/sign-in-response.dto.js';
import { UpdateTokensResponseDto } from '../dto/update-token-response.dto.js';
import { GetToken } from '../decorators/get-auth-token.decorator.js';
import { RecoveryPasswordDto } from '../dto/recovery-password.dto.js';
import { UpdatePasswordDto } from '../dto/update-password.dto.js';
import { SkipAuth } from '../decorators/skip-auth.decorator.js';
import { RefreshTokenGuard } from '../guards/refresh-token.guard.js';
import { GetCurrentUser } from '../../common/decorators/get-current-user.js';
import { RecoveryTokenGuard } from '../guards/recovery-token.guard.js';
import { IUserRequest } from '../../common/interfaces/user-request.interface.js';
import { GetFingerprints } from '../decorators/get-fingerprints.decorator.js';

@SkipAuth()
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('sign-up')
  async signUp(
    @Body() credentials: SignUpDto,
    @GetFingerprints() fingerprint: string,
  ): Promise<SignUpResponseDto> {
    return this.authService.signUp({ ...credentials, fingerprint });
  }

  @Post('sign-in')
  async signIn(
    @Body() credentials: SignInDto,
    @GetFingerprints() fingerprint: string,
  ): Promise<SignInResponseDto> {
    return this.authService.signIn({ ...credentials, fingerprint });
  }

  @Post('refresh-tokens')
  @UseGuards(RefreshTokenGuard)
  async refreshTokens(
    @GetToken('rt') refreshToken: string,
    @GetCurrentUser() { userId }: IUserRequest,
    @GetFingerprints() fingerprint: string,
  ): Promise<UpdateTokensResponseDto> {
    return this.authService.refreshTokens(refreshToken, userId, fingerprint);
  }

  @Delete('log-out')
  @UseGuards(RefreshTokenGuard)
  async logOut(
    @GetToken('rt') refreshToken: string,
    @GetCurrentUser() { userId }: IUserRequest,
  ): Promise<void> {
    return this.authService.logOut(refreshToken, userId);
  }

  @Post('recovery-password')
  async recoveryPassword(
    @Body() { email }: RecoveryPasswordDto,
  ): Promise<void> {
    return this.authService.recoveryPassword(email);
  }

  @Patch('update-password')
  @UseGuards(RecoveryTokenGuard)
  async updatePassword(
    @Body() { password }: UpdatePasswordDto,
    @GetToken('rect') recoveryToken: string,
    @GetCurrentUser() { userId }: IUserRequest,
  ): Promise<void> {
    return this.authService.updatePassword(password, recoveryToken, userId);
  }
}
