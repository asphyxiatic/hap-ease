import {
  CanActivate,
  ExecutionContext,
  NotFoundException,
} from '@nestjs/common';
import { AuthService } from '../../auth/services/auth.service.js';
import config from '../../config/config.js';

export class ConfirmationTokenGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const request = ctx.switchToHttp().getRequest();

    const confirmationToken = request.headers['confirmation-token'];

    if (!confirmationToken) {
      throw new NotFoundException('🚨 token not found!');
    }

    const user = await this.authService.validate(
      confirmationToken,
      config.JWT_CONFIRMATION_SECRET_KEY,
    );

    request['user'] = user;

    return true;
  }
}
