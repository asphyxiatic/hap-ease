import {
  BadRequestException,
  Injectable,
  NotFoundException,
  OnModuleInit,
} from '@nestjs/common';
import { authenticator } from 'otplib';
import config from '../../config/config.js';
import { UsersService } from '../../users/services/users.service.js';
import { toFileStream } from 'qrcode';
import { Response } from 'express';
import { IUserRequest } from '../../common/interfaces/user-request.interface.js';
import { ModuleRef } from '@nestjs/core';

@Injectable()
export class TwoFactorAuthService implements OnModuleInit {
  private userService!: UsersService;

  constructor(private readonly moduleRef: ModuleRef) {}

  onModuleInit() {
    this.userService = this.moduleRef.get(UsersService, { strict: false });
  }

  // -------------------------------------------------------------
  public async generateTwoFactorAuthenticationSecret(
    user: IUserRequest,
  ): Promise<string> {
    const secret = authenticator.generateSecret();

    const otpauthUrl = authenticator.keyuri(
      user.email,
      config.TWO_FACTOR_AUTHENTICATION_APP_NAME,
      secret,
    );

    this.userService.save({
      id: user.userId,
      twoFactorAuthenticationSecret: secret,
    });

    return otpauthUrl;
  }

  // -------------------------------------------------------------
  public async pipeQrCodeStream(
    stream: Response,
    otpauthUrl: string,
  ): Promise<any> {
    return toFileStream(stream, otpauthUrl);
  }

  // -------------------------------------------------------------
  public async twoFactorAuthCodeValid(
    code: string,
    userId: string,
  ): Promise<boolean> {
    const user = await this.userService.findOneFor({ id: userId });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    if (!user.twoFactorAuthenticationSecret) {
      throw new BadRequestException('🚨 code verification error!');
    }

    return authenticator.verify({
      token: code,
      secret: user.twoFactorAuthenticationSecret,
    });
  }
}
