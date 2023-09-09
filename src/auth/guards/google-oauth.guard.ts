import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { GoogleOAuthService } from '../services/google-auth.service.js';

@Injectable()
export class GoogleOAuthGuard extends AuthGuard('google') {
  constructor(private readonly googleOAuthService: GoogleOAuthService) {
    super({
      accessType: 'offline',
    });
  }

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    (await super.canActivate(ctx)) as boolean;

    const request = ctx.switchToHttp().getRequest();

    const googleUser = request.user;

    if (!googleUser) {
      throw new UnauthorizedException('🚨 google authentication error!');
    }

    request['user'] = googleUser;

    return true;
  }
}
