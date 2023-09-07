import {
  Body,
  Controller,
  Delete,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from '../services/auth.service.js';
import { SignUpDto } from '../dto/sign-up.dto.js';
import { SignInDto } from '../dto/sign-in.dto.js';
import { SignUpResponseDto } from '../dto/sign-up-response.dto.js';
import { SignInResponseDto } from '../dto/sign-in-response.dto.js';
import { UpdateTokensResponseDto } from '../dto/update-token.dto.js';
import { GetAuthToken } from '../decorators/get-auth-token.decorator.js';
import { RecoveryPasswordDto } from '../dto/recovery-password.dto.js';
import { UpdatePasswordDto } from '../dto/update-password.dto.js';
import { NotEmptyAuthorizationGuard } from '../guards/not-empty-authorization.guard.js';
import { User } from '../../users/entities/user.entity.js';
import { GoogleAuthService } from '../services/google-auth.service.js';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly googleAuthService: GoogleAuthService,
  ) {}

  @Post('sign-up')
  async signUp(@Body() credentials: SignUpDto): Promise<SignUpResponseDto> {
    return this.authService.signUp(credentials);
  }

  @Post('sign-in')
  async signIn(@Body() credentials: SignInDto): Promise<SignInResponseDto> {
    return this.authService.signIn(credentials);
  }

  @Post('update-tokens')
  @UseGuards(NotEmptyAuthorizationGuard)
  async updateTokens(
    @GetAuthToken() refreshToken: string,
  ): Promise<UpdateTokensResponseDto> {
    return this.authService.updateTokens(refreshToken);
  }

  @Delete('log-out')
  @UseGuards(NotEmptyAuthorizationGuard)
  async logOut(@GetAuthToken() refreshToken: string): Promise<void> {
    return this.authService.logOut(refreshToken);
  }

  @Post('recovery-password')
  async recoveryPassword(
    @Body() { email }: RecoveryPasswordDto,
  ): Promise<void> {
    return this.authService.recoveryPassword(email);
  }

  @Patch('update-password')
  @UseGuards(NotEmptyAuthorizationGuard)
  async updatePassword(
    @Body() { password }: UpdatePasswordDto,
    @GetAuthToken() recoveryToken: string,
  ): Promise<void> {
    return this.authService.updatePassword(password, recoveryToken);
  }

  @Post('google-authentication')
  @UseGuards(NotEmptyAuthorizationGuard)
  async googleAuthentication(
    @GetAuthToken() googleAccessToken: string,
  ): Promise<User> {
    return this.googleAuthService.authenticate(googleAccessToken);
  }
}
