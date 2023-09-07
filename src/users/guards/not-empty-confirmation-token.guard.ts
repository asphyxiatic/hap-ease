import { CanActivate, ExecutionContext } from '@nestjs/common';

export class NotEmptyConfirmationTokenGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const request = ctx.switchToHttp().getRequest();

    const confirmationToken = request.headers['confirmation-token'];

    return !!confirmationToken;
  }
}
