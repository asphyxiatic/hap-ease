import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { AuthService } from '../services/auth.service.js';

import config from '../../config/config.js';

@Injectable()
export class RecoveryTokenGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const request = ctx.switchToHttp().getRequest();

    const refreshToken = this.authService.extractTokenFromHeader(request);

    const user = await this.authService.validate(
      refreshToken,
      config.JWT_RECOVERY_SECRET_KEY,
    );

    request['user'] = user;

    return true;
  }
}
