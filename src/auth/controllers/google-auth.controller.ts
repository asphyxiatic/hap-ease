import { Controller, Get, UseGuards } from '@nestjs/common';
import { GoogleOAuthService } from '../services/google-auth.service.js';
import { SkipAuth } from '../decorators/skip-auth.decorator.js';
import { GetCurrentUser } from '../../common/decorators/get-current-user.js';
import { GoogleOAuthGuard } from '../guards/google-oauth.guard.js';
import { IUserRequestParams } from '../../common/interfaces/user-request-params.interface.js';

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
    @GetCurrentUser() googleUser: IUserRequestParams,
  ): Promise<string> {
    if (googleUser) {
      return 'Authenticated';
    } else {
      return 'Not Authenticated';
    }
  }
}
