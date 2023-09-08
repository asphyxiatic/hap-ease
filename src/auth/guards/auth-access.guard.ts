import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '../services/auth.service.js';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/skip-auth.decorator.js';
import config from '../../config/config.js';

@Injectable()
export class AuthAccessGuard implements CanActivate {
  constructor(private authService: AuthService, private reflector: Reflector) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const request = ctx.switchToHttp().getRequest();

    const token = this.authService.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('🚨 token not found!');
    }

    const user = await this.authService.validate(
      token,
      config.JWT_ACCESS_SECRET_KEY,
    );

    request['user'] = user;

    return true;
  }
}
