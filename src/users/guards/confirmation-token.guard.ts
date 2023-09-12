import {
  CanActivate,
  ExecutionContext,
  Injectable,
  NotFoundException,
  OnModuleInit,
} from '@nestjs/common';
import { AuthService } from '../../auth/services/auth.service.js';
import config from '../../config/config.js';
import { ModuleRef } from '@nestjs/core';

@Injectable()
export class ConfirmationTokenGuard implements CanActivate, OnModuleInit {
  private authService!: AuthService;

  constructor(private readonly moduleRef: ModuleRef) {}

  onModuleInit() {
    this.authService = this.moduleRef.get(AuthService, { strict: false });
  }

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
