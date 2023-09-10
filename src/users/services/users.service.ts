import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { FindOptionsWhere, Repository } from 'typeorm';
import { User } from '../entities/user.entity.js';
import config from '../../config/config.js';
import * as bcrypt from 'bcrypt';
import { ITokenPayload } from '../../common/interfaces/token-payload.interface.js';
import { JwtToolsService } from '../../jwt/services/jwt-tools.service.js';
import { EmailService } from '../../mailer/services/email.service.js';
import { TemplatesDiscriptionEnum } from '../../mailer/enums/templates-discription.enum.js';
import { TemplatesEnum } from '../../mailer/enums/templates.enum.js';
import { EncryptionService } from '../../encryption/services/encryption.service.js';

@Injectable()
export class UsersService {
  private readonly saltRounds = 5;
  private readonly JWT_CONFIRMATION_SECRET_KEY =
    config.JWT_CONFIRMATION_SECRET_KEY;

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtToolsSerivce: JwtToolsService,
    private readonly emailService: EmailService,
    private readonly encryptionService: EncryptionService,
  ) {}

  // -------------------------------------------------------------
  public async findOneFor(
    findOptions: FindOptionsWhere<User>,
  ): Promise<User | null> {
    const user = await this.userRepository.findOne({ where: findOptions });
    return user;
  }

  // -------------------------------------------------------------
  public async save(userOptions: Partial<User>): Promise<User> {
    try {
      return this.userRepository.save(userOptions);
    } catch (error: any) {
      throw new InternalServerErrorException('🚨 ' + error.message);
    }
  }

  // -------------------------------------------------------------
  public async changePassword(
    newPassword: string,
    userId: string,
  ): Promise<void> {
    const user = await this.findOneFor({ id: userId });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    const hashedPassword = bcrypt.hashSync(newPassword, this.saltRounds);

    this.save({
      id: user.id,
      password: hashedPassword,
    });
  }

  // -------------------------------------------------------------
  public async emailConfirmationRequest(email: string): Promise<void> {
    const user = await this.findOneFor({ email: email });

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

    this.save({
      id: user.id,
      confirmationToken: hashedConfirmationToken,
    });

    const contextForEmail = {
      nickname: user.nickname,
      confirmationToken: confirmationToken,
    };

    this.emailService.sendTempleteByEmail(
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
    const user = await this.findOneFor({ id: userId });

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

    this.save({
      id: user.id,
      confirmationToken: null,
      active: true,
    });
  }
}
