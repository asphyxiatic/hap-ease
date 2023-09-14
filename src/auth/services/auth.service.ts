import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { SignUpDto } from '../dto/sign-up.dto.js';
import { SignInDto } from '../dto/sign-in.dto.js';
import config from '../../config/config.js';
import { SignUpResponseDto } from '../dto/sign-up-response.dto.js';
import { SignInResponseDto } from '../dto/sign-in-response.dto.js';
import { UsersService } from '../../users/services/users.service.js';
import { User } from '../../users/entities/user.entity.js';
import { UpdateTokensResponseDto } from '../dto/update-token-response.dto.js';
import { TokensService } from '../../tokens/services/tokens.service.js';
import { JwtToolsService } from '../../jwt/services/jwt-tools.service.js';
import { ITokenPayload } from '../../common/interfaces/token-payload.interface.js';
import { EmailService } from '../../mailer/services/email.service.js';
import { TemplatesEnum } from '../../mailer/enums/templates.enum.js';
import { TemplatesDiscriptionEnum } from '../../mailer/enums/templates-discription.enum.js';
import { Request } from 'express';
import { ITokens } from '../interfaces/tokens.interface.js';
import { IUserRequest } from '../../common/interfaces/user-request.interface.js';
import { EncryptionService } from '../../encryption/services/encryption.service.js';
import { SignIn2FAResponseDto } from '../dto/sign-in-2fa-response.dto.js';
import { TwoFactorAuthService } from './two-factor-auth.service.js';
import { IContextForRecovery } from '../interfaces/context-mail-for-recovery.interface.js';
import { plainToInstance } from 'class-transformer';

@Injectable()
export class AuthService {
  private readonly saltRounds = 5;
  private readonly JWT_ACCESS_SECRET_KEY = config.JWT_ACCESS_SECRET_KEY;
  private readonly JWT_REFRESH_SECRET_KEY = config.JWT_REFRESH_SECRET_KEY;
  private readonly JWT_RECOVERY_SECRET_KEY = config.JWT_RECOVERY_SECRET_KEY;

  constructor(
    private readonly tokensService: TokensService,
    private readonly jwtToolsSerivce: JwtToolsService,
    private readonly usersService: UsersService,
    private readonly emailService: EmailService,
    private readonly encryptionService: EncryptionService,
    private readonly twoFactorAuthService: TwoFactorAuthService,
  ) {}

  // -------------------------------------------------------------
  public async signUp({
    email,
    nickname,
    password,
    fingerprint,
  }: SignUpDto & { fingerprint: string }): Promise<SignUpResponseDto> {
    const existingUser = await this.usersService.findOneFor({
      email: email,
    });

    if (existingUser) {
      throw new ConflictException('🚨 user is already exist!');
    }

    const hashedPassword = bcrypt.hashSync(password, this.saltRounds);

    const newUserProps: Partial<User> = {
      email: email,
      nickname: nickname,
      password: hashedPassword,
    };

    const newUser = await this.usersService.save(newUserProps);

    const tokens = await this.createPairTokens(newUser.id, newUser.email);

    await this.tokensService.save({
      userId: newUser.id,
      value: tokens.refreshToken,
      fingerprint: fingerprint,
    });

    const userInfo = {
      user: {
        email: newUser.email,
        nickname: newUser.nickname,
        avatar: newUser.avatar,
      },
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    };

    return userInfo;
  }

  // -------------------------------------------------------------
  public async signIn({
    email,
    password,
    fingerprint,
  }: SignInDto & { fingerprint: string }): Promise<
    SignInResponseDto | SignIn2FAResponseDto
  > {
    const user = await this.usersService.findOneFor({ email: email });

    if (!user) {
      throw new BadRequestException(
        '🚨 invalid login information or password!',
      );
    }

    if (!user.password) {
      throw new BadRequestException(
        '🚨 invalid login information or password!',
      );
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);

    if (!passwordIsValid) {
      throw new BadRequestException(
        '🚨 invalid login information or password!',
      );
    }

    if (user.isTwoFactorAuthenticationEnabled) {
      const twoFactorAuthTicketPayload: ITokenPayload = {
        sub: user.id,
        email: user.email,
      };

      const twoFactorAuthTicket = await this.jwtToolsSerivce.createToken(
        twoFactorAuthTicketPayload,
        config.JWT_2FA_SECRET_KEY,
        '5m',
      );

      const signInResponse = { ticket: twoFactorAuthTicket };

      return signInResponse;
    }

    const tokens = await this.createPairTokens(user.id, user.email);

    await this.tokensService.save({
      userId: user.id,
      value: tokens.refreshToken,
      fingerprint: fingerprint,
    });

    const signInResponse = {
      user: {
        email: user.email,
        nickname: user.nickname,
        avatar: user.avatar,
      },
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    };

    return signInResponse;
  }

  // -------------------------------------------------------------
  public async signIn2FA(
    code: string,
    user: IUserRequest,
    fingerprint: string,
  ): Promise<SignInResponseDto> {
    const codeIsValid = await this.twoFactorAuthService.twoFactorAuthCodeValid(
      code,
      user.userId,
    );

    if (!codeIsValid) {
      throw new UnauthorizedException('🚨 wrong authentication code!');
    }

    const tokens = await this.createPairTokens(user.userId, user.email);

    await this.tokensService.save({
      userId: user.userId,
      value: tokens.refreshToken,
      fingerprint: fingerprint,
    });

    const userInfo = {
      user: {
        email: user.email,
        nickname: user.nickname,
        avatar: user.avatar,
      },
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    };

    return userInfo;
  }

  // -------------------------------------------------------------
  public async validate(
    token: string,
    jwtSecret: string,
  ): Promise<IUserRequest> {
    const { userId } = await this.jwtToolsSerivce.decodeToken(token, jwtSecret);

    const user = await this.usersService.findOneFor({ id: userId });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    return {
      userId: user.id,
      email: user.email,
      avatar: user.avatar,
      nickname: user.nickname,
    };
  }

  // -------------------------------------------------------------
  public async recoveryPassword(email: string): Promise<void> {
    const user = await this.usersService.findOneFor({ email });

    if (!user) {
      throw new NotFoundException('🚨 user not found');
    }

    if (!user.password) {
      throw new BadRequestException('🚨 password recovery error!');
    }

    const payload: ITokenPayload = {
      sub: user.id,
      email: email,
    };

    const recoveryToken = await this.jwtToolsSerivce.createToken(
      payload,
      this.JWT_RECOVERY_SECRET_KEY,
      '5m',
    );

    const encryptRecoveryToken = await this.encryptionService.encrypt(
      recoveryToken,
    );

    const hashedRecoveryToken = bcrypt.hashSync(
      encryptRecoveryToken,
      this.saltRounds,
    );

    await this.usersService.save({
      ...user,
      recoveryToken: hashedRecoveryToken,
    });

    let twoFactorEnabled;

    user.isTwoFactorAuthenticationEnabled
      ? (twoFactorEnabled = true)
      : (twoFactorEnabled = false);

    const contextForEmail: IContextForRecovery = {
      nickname: user.nickname,
      recoveryToken: recoveryToken,
      twoFactorEnabled: twoFactorEnabled,
    };

    await this.emailService.sendTempleteByEmail(
      email,
      TemplatesEnum.RECOVERY_PASSWORD,
      TemplatesDiscriptionEnum.RECOVERY_PASSWORD,
      contextForEmail,
    );
  }

  // -------------------------------------------------------------
  public async updatePassword(
    password: string,
    code: string | undefined,
    recoveryToken: string,
    userId: string,
  ): Promise<void> {
    const user = await this.usersService.findOneFor({
      id: userId,
    });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    if (!user.recoveryToken) {
      throw new UnauthorizedException('🚨 token is invalid!');
    }

    const encryptRecoveryToken = await this.encryptionService.encrypt(
      recoveryToken,
    );

    const recoveryTokenIsValid = bcrypt.compareSync(
      encryptRecoveryToken,
      user.recoveryToken,
    );

    if (!recoveryTokenIsValid) {
      throw new UnauthorizedException('🚨 token is invalid!');
    }

    if (user.isTwoFactorAuthenticationEnabled) {
      if (!code) {
        throw new ForbiddenException('🚨 wrong authentication code!');
      }

      const codeIsValid =
        await this.twoFactorAuthService.twoFactorAuthCodeValid(code, userId);

      if (!codeIsValid) {
        throw new UnauthorizedException('🚨 wrong authentication code!');
      }
    }

    const hashedPassword = bcrypt.hashSync(password, this.saltRounds);

    await this.usersService.save({
      id: user.id,
      password: hashedPassword,
      recoveryToken: null,
    });
  }

  // -------------------------------------------------------------
  public async changePassword(
    newPassword: string,
    code: string | undefined,
    userId: string,
  ): Promise<void> {
    const user = await this.usersService.findOneFor({ id: userId });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    if (!user.password) {
      throw new BadRequestException('🚨 password change error!');
    }

    if (user.isTwoFactorAuthenticationEnabled) {
      if (!code) {
        throw new ForbiddenException('🚨 wrong authentication code!');
      }

      const codeIsValid =
        await this.twoFactorAuthService.twoFactorAuthCodeValid(code, userId);

      if (!codeIsValid) {
        throw new UnauthorizedException('🚨 wrong authentication code!');
      }
    }

    const hashedPassword = bcrypt.hashSync(newPassword, this.saltRounds);

    await this.usersService.save({
      id: user.id,
      password: hashedPassword,
    });
  }

  // -------------------------------------------------------------
  public async logOut(refreshToken: string, userId: string): Promise<void> {
    const refreshTokensFromDB = await this.tokensService.find({
      userId: userId,
    });

    const encryptRefreshToken = await this.encryptionService.encrypt(
      refreshToken,
    );

    const extractTokenFromDB = refreshTokensFromDB.find((token) =>
      bcrypt.compareSync(encryptRefreshToken, token.value),
    );

    if (!extractTokenFromDB) {
      throw new UnauthorizedException('🚨 token is invalid!');
    }

    await this.tokensService.delete(extractTokenFromDB.value);
  }

  // -------------------------------------------------------------
  public async refreshTokens(
    refreshToken: string,
    userId: string,
    fingerprint: string,
  ): Promise<UpdateTokensResponseDto> {
    const refreshTokensFromDB = await this.tokensService.find({
      userId: userId,
    });

    const encryptRefreshToken = await this.encryptionService.encrypt(
      refreshToken,
    );

    const refreshTokenIsValid = refreshTokensFromDB.find(
      (token) =>
        token.fingerprint === fingerprint &&
        bcrypt.compareSync(encryptRefreshToken, token.value),
    );

    if (!refreshTokenIsValid) {
      throw new UnauthorizedException('🚨 token is invalid!');
    }

    const user = await this.usersService.findOneFor({ id: userId });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    const newTokens = await this.createPairTokens(user.id, user.email);

    await this.tokensService.save({
      ...refreshTokenIsValid,
      value: newTokens.refreshToken,
      fingerprint,
    });

    const userInfo = {
      user: {
        email: user.email,
        nickname: user.nickname,
        avatar: user.avatar,
      },
      access_token: newTokens.accessToken,
      refresh_token: newTokens.refreshToken,
    };

    return userInfo;
  }

  // -------------------------------------------------------------
  public async extractTokenFromHeader(request: Request): Promise<string> {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    if (type !== 'Bearer') {
      throw new UnauthorizedException('🚨 token not found!');
    }
    return token;
  }

  // -------------------------------------------------------------
  public async createPairTokens(
    userId: string,
    email: string,
  ): Promise<ITokens> {
    const payloadForAccessToken: ITokenPayload = {
      sub: userId,
      email: email,
    };
    const accessToken = await this.jwtToolsSerivce.createToken(
      payloadForAccessToken,
      this.JWT_ACCESS_SECRET_KEY,
      '5m',
    );

    const payloadForRefreshToken: ITokenPayload = {
      sub: userId,
      email: email,
    };

    const refreshToken = await this.jwtToolsSerivce.createToken(
      payloadForRefreshToken,
      this.JWT_REFRESH_SECRET_KEY,
      '60d',
    );

    return { accessToken, refreshToken };
  }
}
