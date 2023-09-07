import {
  CanActivate,
  ExecutionContext,
  Injectable,
  NotFoundException,
} from '@nestjs/common';

@Injectable()
export class NotEmptyAuthorizationGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const request = ctx.switchToHttp().getRequest();

    const authorization = request.headers.authorization;

    if (!authorization) {
      throw new NotFoundException('🚨 token not found');
    }

    return true;
  }
}
