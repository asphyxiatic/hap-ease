import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { SignUpDto } from '../dto/sign-up.dto.js';
import { SignInDto } from '../dto/sign-in.dto.js';
import { JwtService } from '@nestjs/jwt';
import config from '../../config/config.js';
import { randomUUID } from 'crypto';
import { SignUpResponseDto } from '../dto/sign-up-response.dto.js';
import { SignInResponseDto } from '../dto/sign-in-response.dto.js';
import { ICreateTokensResponse } from '../interfaces/create-tokens-response.interface.js';
import { ITokenPayload } from '../interfaces/token-payload.interface.js';
import { IValidateResponse } from '../interfaces/validate-response.interface.js';
import { UsersService } from '../../users/services/user.service.js';
import { User } from '../../users/entities/user.entity.js';
import { UpdateTokensDto } from '../dto/update-token.dto.js';
import { TokensService } from '../../tokens/services/token.service.js';
import { IDecodeTokenResponse } from '../interfaces/decode-token-response.interface.js';

@Injectable()
export class AuthService {
  constructor(
    private readonly tokensService: TokensService,
    private readonly jwtService: JwtService,
    private readonly userService: UsersService,
  ) {}

  // -------------------------------------------------------------
  public async signUp({
    email,
    nickname,
    password,
  }: SignUpDto): Promise<SignUpResponseDto> {
    const existingUser = await this.userService.findOneFor({
      email: email,
    });

    if (existingUser) {
      throw new UnauthorizedException('🚨 user is already exist!');
    }

    const hashedPassword = bcrypt.hashSync(password, 5);

    const newUserProps: Partial<User> = {
      email: email,
      nickname: nickname,
      password: hashedPassword,
    };

    const newUser = await this.userService.save(newUserProps);

    const tokens = await this.createTokens(newUser.id, newUser.email);

    const hashedRefreshToken = bcrypt.hashSync(tokens.refreshToken, 5);

    this.tokensService.save({
      userId: newUser.id,
      value: hashedRefreshToken,
    });

    return {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    };
  }

  // -------------------------------------------------------------
  public async signIn({
    email,
    password,
  }: SignInDto): Promise<SignInResponseDto> {
    const user = await this.userService.findOneFor({ email: email });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);

    if (!passwordIsValid) {
      throw new UnauthorizedException('🚨 incorrect password!');
    }

    const tokens = await this.createTokens(user.id, user.email);

    const hashedRefreshToken = bcrypt.hashSync(tokens.refreshToken, 5);

    this.tokensService.save({
      userId: user.id,
      value: hashedRefreshToken,
    });

    return {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    };
  }

  // -------------------------------------------------------------
  public async validate(accessToken: string): Promise<IValidateResponse> {
    const { userId } = await this.decodeToken(
      accessToken,
      config.JWT_ACCESS_SECRET_KEY,
    );

    const user = await this.userService.findOneFor({ id: userId });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    return { userId: user!.id };
  }

  // -------------------------------------------------------------
  public async logOut(refreshToken: string): Promise<void> {
    const { userId } = await this.decodeToken(
      refreshToken,
      config.JWT_REFRESH_SECRET_KEY,
    );

    const refreshTokensFromDB = await this.tokensService.find({
      userId: userId,
    });

    const extractTokenFromDB = refreshTokensFromDB.find((token) =>
      bcrypt.compareSync(refreshToken, token.value),
    );

    if (!extractTokenFromDB) {
      throw new InternalServerErrorException('🚨 failed to log-out');
    }

    this.tokensService.delete(extractTokenFromDB.value);
  }

  // -------------------------------------------------------------
  public async updateTokens(refreshToken: string): Promise<UpdateTokensDto> {
    const { userId } = await this.decodeToken(
      refreshToken,
      config.JWT_REFRESH_SECRET_KEY,
    );

    const refreshTokensFromDB = await this.tokensService.find({
      userId: userId,
    });

    const refreshTokenIsValid = refreshTokensFromDB.find((token) =>
      bcrypt.compareSync(refreshToken, token.value),
    );

    if (!refreshTokenIsValid) {
      throw new UnauthorizedException('🚨 refresh_token is invalid!');
    }

    const user = await this.userService.findOneFor({ id: userId });

    if (!user) {
      throw new NotFoundException('🚨 user not found!');
    }

    const newTokens = await this.createTokens(user.id, user.email);

    const hashedRefreshToken = bcrypt.hashSync(newTokens.refreshToken, 5);

    this.tokensService.save({
      ...refreshTokenIsValid,
      value: hashedRefreshToken,
    });

    return {
      access_token: newTokens.accessToken,
      refresh_token: newTokens.refreshToken,
    };
  }

  // -------------------------------------------------------------
  private async createTokens(
    userId: string,
    email: string,
  ): Promise<ICreateTokensResponse> {
    const payload: ITokenPayload = { sub: userId, email: email };

    const accessToken = await this.jwtService.signAsync(payload, {
      secret: config.JWT_ACCESS_SECRET_KEY,
      expiresIn: '5m',
    });

    const refreshToken = await this.jwtService.signAsync(
      { unique: randomUUID(), ...payload },
      {
        secret: config.JWT_REFRESH_SECRET_KEY,
        expiresIn: '60d',
      },
    );

    return {
      accessToken: accessToken,
      refreshToken: refreshToken,
    };
  }

  // -------------------------------------------------------------
  private async decodeToken(
    token: string,
    secret: string,
  ): Promise<IDecodeTokenResponse> {
    const decodeToken: ITokenPayload = await this.jwtService
      .verifyAsync(token, { secret: secret })
      .catch((error: any) => {
        throw new UnauthorizedException('🚨 token is invalid!');
      });

    return {
      userId: decodeToken.sub,
      email: decodeToken.email,
    };
  }
}
