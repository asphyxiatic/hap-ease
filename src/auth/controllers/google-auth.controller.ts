import { Controller, Get, UseGuards } from '@nestjs/common';
import { GoogleOAuthService } from '../services/google-auth.service.js';
import { SkipAuth } from '../decorators/skip-auth.decorator.js';
import { GetCurrentUser } from '../../common/decorators/get-current-user.js';
import { GoogleOAuthGuard } from '../guards/google-oauth.guard.js';
import { GoogleSignInResponseDto } from '../dto/google-sign-in-response.dto.js';
import { IGoogleUser } from '../interfaces/google-user.interface.js';

@SkipAuth()
@Controller('google-auth')
export class GoogleOAuthController {
  constructor(private readonly googleOAuthService: GoogleOAuthService) {}

  @Get()
  @UseGuards(GoogleOAuthGuard)
  async googleSignIn(): Promise<void> {}

  @Get('redirect')
  @UseGuards(GoogleOAuthGuard)
  async googleRedirect(
    @GetCurrentUser() googleUser: IGoogleUser,
  ): Promise<GoogleSignInResponseDto> {
    return this.googleOAuthService.googleSignIn(googleUser);
  }

  
}
