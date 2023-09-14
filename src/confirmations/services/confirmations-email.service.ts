import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { UsersService } from '../../users/services/users.service.js';
import { JwtToolsService } from '../../jwt/services/jwt-tools.service.js';
import config from '../../config/config.js';
import { ITokenPayload } from '../../common/interfaces/token-payload.interface.js';
import { EmailService } from '../../mailer/services/email.service.js';
import { EncryptionService } from '../../encryption/services/encryption.service.js';
import * as bcrypt from 'bcrypt';
import { IContextForConfirmationEmail } from '../interfaces/context-mail-for-confirmation-email.interface.js';
import { TemplatesEnum } from '../../mailer/enums/templates.enum.js';
import { TemplatesDiscriptionEnum } from '../../mailer/enums/templates-discription.enum.js';

@Injectable()
export class ConfirmationsEmailService {
  private readonly saltRounds = 5;
  private readonly JWT_CONFIRMATION_SECRET_KEY =
    config.JWT_CONFIRMATION_SECRET_KEY;

  constructor(
    private readonly userService: UsersService,
    private readonly encryptionService: EncryptionService,
    private readonly jwtToolsSerivce: JwtToolsService,
    private readonly emailService: EmailService,
  ) {}

  // -------------------------------------------------------------
  public async emailConfirmationRequest(email: string): Promise<void> {
    const user = await this.userService.findOneFor({ email: email });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    if (user.active) {
      throw new BadRequestException('🚨 email has already been confirmed!');
    }

    const payload: ITokenPayload = {
      sub: user.id,
      email: user.email,
    };

    const confirmationToken = await this.jwtToolsSerivce.createToken(
      payload,
      this.JWT_CONFIRMATION_SECRET_KEY,
      '5m',
    );

    const encryptConfirmationToken = await this.encryptionService.encrypt(
      confirmationToken,
    );

    const hashedConfirmationToken = bcrypt.hashSync(
      encryptConfirmationToken,
      this.saltRounds,
    );

    await this.userService.save({
      id: user.id,
      confirmationToken: hashedConfirmationToken,
    });

    const contextForEmail: IContextForConfirmationEmail = {
      nickname: user.nickname,
      confirmationToken: confirmationToken,
    };

    await this.emailService.sendTempleteByEmail(
      user.email,
      TemplatesEnum.СONFIRMATION_EMAIL,
      TemplatesDiscriptionEnum.СONFIRMATION_EMAIL,
      contextForEmail,
    );
  }

  // -------------------------------------------------------------
  public async confirmationEmail(
    confirmationToken: string,
    userId: string,
  ): Promise<void> {
    const user = await this.userService.findOneFor({ id: userId });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    if (!user.confirmationToken) {
      throw new InternalServerErrorException('🚨 token is invalid!');
    }

    const encryptConfirmationToken = await this.encryptionService.encrypt(
      confirmationToken,
    );

    const confirmationTokenIsValid = bcrypt.compareSync(
      encryptConfirmationToken,
      user.confirmationToken,
    );

    if (!confirmationTokenIsValid) {
      throw new InternalServerErrorException('🚨 token is invalid!');
    }

    await this.userService.save({
      id: user.id,
      confirmationToken: null,
      active: true,
    });
  }
}
