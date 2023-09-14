import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { authenticator } from 'otplib';
import config from '../../config/config.js';
import { UsersService } from '../../users/services/users.service.js';
import { toFileStream } from 'qrcode';
import { Response } from 'express';
import { IUserRequest } from '../../common/interfaces/user-request.interface.js';
import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcrypt';

@Injectable()
export class TwoFactorAuthService {
  private readonly saltRounds = 5;

  constructor(private readonly userService: UsersService) {}

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

    await this.userService.save({
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

  public async generateReservationCode2FA(userId: string): Promise<string> {
    const reservationCode = uuidv4().substring(0, 6);

    const hashedReservationCode = bcrypt.hashSync(
      reservationCode,
      this.saltRounds,
    );

    await this.userService.save({
      id: userId,
      twoFactorReservationCode: hashedReservationCode,
    });

    return reservationCode;
  }
}
