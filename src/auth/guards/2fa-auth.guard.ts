import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { AuthService } from '../services/auth.service.js';
import config from '../../config/config.js';


@Injectable()
export class TwoFactorAuthGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const request = ctx.switchToHttp().getRequest();

    const twoFactorAuthTicket = await this.authService.extractTokenFromHeader(
      request,
    );

    const user = this.authService.validate(
      twoFactorAuthTicket,
      config.JWT_2FA_SECRET_KEY,
    );

    request['user'] = user;

    return true;
  }
}
