import {
  Body,
  Controller,
  Post,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { TwoFactorAuthService } from '../services/two-factor-auth.service.js';
import { GetCurrentUser } from '../../common/decorators/get-current-user.js';
import { IUserRequest } from '../../common/interfaces/user-request.interface.js';
import { Response } from 'express';
import { TurnOnTwoFactorAuthDto } from '../dto/turn-on-2fa-auth.dto.js';
import { UsersService } from '../../users/services/users.service.js';

@Controller('2fa')
export class TwoFactorAuthController {
  constructor(
    private readonly twoFactorAuthService: TwoFactorAuthService,
    private readonly userService: UsersService,
  ) {}

  @Post('generate')
  async register(
    @Res() response: Response,
    @GetCurrentUser() user: IUserRequest,
  ): Promise<any> {
    const otpauthUrl =
      await this.twoFactorAuthService.generateTwoFactorAuthenticationSecret(
        user,
      );
    return this.twoFactorAuthService.pipeQrCodeStream(response, otpauthUrl);
  }

  @Post('turn-on')
  async turnOnTwoFactorAuthentication(
    @Body() { code }: TurnOnTwoFactorAuthDto,
    @GetCurrentUser() { userId }: IUserRequest,
  ): Promise<void> {
    const codeIsValid = await this.twoFactorAuthService.twoFactorAuthCodeValid(
      code,
      userId,
    );

    if (!codeIsValid) {
      throw new UnauthorizedException('🚨 wrong authentication code!');
    }

    await this.userService.turnOnTwoFactorAuth(userId);
  }
}
