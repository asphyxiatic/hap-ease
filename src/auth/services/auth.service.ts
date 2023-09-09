import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { SignUpDto } from '../dto/sign-up.dto.js';
import { SignInDto } from '../dto/sign-in.dto.js';
import config from '../../config/config.js';
import { randomUUID } from 'crypto';
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

    const hashedRefreshToken = bcrypt.hashSync(
      tokens.refreshToken,
      this.saltRounds,
    );

    this.tokensService.save({
      userId: newUser.id,
      value: hashedRefreshToken,
      fingerprint: fingerprint,
    });

    return {
      user: {
        email: newUser.email,
        nickname: newUser.nickname,
        avatar: newUser.avatar,
      },
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    };
  }

  // -------------------------------------------------------------
  public async signIn({
    email,
    password,
    fingerprint,
  }: SignInDto & { fingerprint: string }): Promise<SignInResponseDto> {
    const user = await this.usersService.findOneFor({ email: email });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
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

    const tokens = await this.createPairTokens(user.id, user.email);

    const hashedRefreshToken = bcrypt.hashSync(
      tokens.refreshToken,
      this.saltRounds,
    );

    this.tokensService.save({
      userId: user.id,
      value: hashedRefreshToken,
      fingerprint: fingerprint,
    });

    return {
      user: {
        email: user.email,
        nickname: user.nickname,
        avatar: user.avatar,
      },
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    };
  }

  // -------------------------------------------------------------
  public async validate(
    accessToken: string,
    jwtSecret: string,
  ): Promise<IUserRequest> {
    const { userId } = await this.jwtToolsSerivce.decodeToken(
      accessToken,
      jwtSecret,
    );

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

    const payload: ITokenPayload = {
      unique: randomUUID(),
      sub: user.id,
      email: email,
    };

    const recoveryToken = await this.jwtToolsSerivce.createToken(
      payload,
      this.JWT_RECOVERY_SECRET_KEY,
      '5m',
    );

    const hashedRecoveryToken = bcrypt.hashSync(recoveryToken, this.saltRounds);

    this.usersService.save({
      ...user,
      recoveryToken: hashedRecoveryToken,
    });

    const context = {
      nickname: user.nickname,
      recoveryToken: recoveryToken,
    };

    this.emailService.sendTemplete(
      email,
      TemplatesEnum.RECOVERY_PASSWORD,
      TemplatesDiscriptionEnum.RECOVERY_PASSWORD,
      context,
    );
  }

  // -------------------------------------------------------------
  public async updatePassword(
    password: string,
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

    const recoveryTokenIsValid = bcrypt.compareSync(
      recoveryToken,
      user.recoveryToken,
    );

    if (!recoveryTokenIsValid) {
      throw new UnauthorizedException('🚨 token is invalid!');
    }

    this.usersService.save({
      id: user.id,
      recoveryToken: null,
    });

    const hashedPassword = bcrypt.hashSync(password, this.saltRounds);

    this.usersService.save({
      id: user.id,
      password: hashedPassword,
    });
  }

  // -------------------------------------------------------------
  public async logOut(refreshToken: string, userId: string): Promise<void> {
    const refreshTokensFromDB = await this.tokensService.find({
      userId: userId,
    });

    const extractTokenFromDB = refreshTokensFromDB.find((token) =>
      bcrypt.compareSync(refreshToken, token.value),
    );

    if (!extractTokenFromDB) {
      throw new UnauthorizedException('🚨 token is invalid!');
    }

    this.tokensService.delete(extractTokenFromDB.value);
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

    const refreshTokenIsValid = refreshTokensFromDB.find(
      (token) =>
        token.fingerprint === fingerprint &&
        bcrypt.compareSync(refreshToken, token.value),
    );

    if (!refreshTokenIsValid) {
      throw new UnauthorizedException('🚨 token is invalid!');
    }

    const user = await this.usersService.findOneFor({ id: userId });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    const newTokens = await this.createPairTokens(user.id, user.email);

    const hashedRefreshToken = bcrypt.hashSync(
      newTokens.refreshToken,
      this.saltRounds,
    );

    this.tokensService.save({
      ...refreshTokenIsValid,
      value: hashedRefreshToken,
      fingerprint,
    });

    return {
      user: {
        email: user.email,
        nickname: user.nickname,
        avatar: user.avatar,
      },
      access_token: newTokens.accessToken,
      refresh_token: newTokens.refreshToken,
    };
  }

  // -------------------------------------------------------------
  public extractTokenFromHeader(request: Request): string {
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
      unique: randomUUID(),
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
