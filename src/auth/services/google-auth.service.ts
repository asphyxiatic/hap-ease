import { ConflictException, Injectable } from '@nestjs/common';
import { UsersService } from '../../users/services/users.service.js';
import { IGoogleUser } from '../interfaces/google-user.interface.js';
import { GoogleSignInResponseDto } from '../dto/google-sign-in-response.dto.js';
import { AuthService } from './auth.service.js';
import * as bcrypt from 'bcrypt';
import { TokensService } from '../../tokens/services/tokens.service.js';

@Injectable()
export class GoogleOAuthService {
  private readonly saltRounds = 5;

  constructor(
    private readonly usersService: UsersService,
    private readonly authService: AuthService,
    private readonly tokensService: TokensService,
  ) {}

  // -------------------------------------------------------------
  public async googleSignIn(
    googleUser: IGoogleUser,
    fingerprint: string,
  ): Promise<GoogleSignInResponseDto> {
    const user = await this.usersService.findOneFor({
      email: googleUser.email,
    });

    if (!user) {
      const newUser = await this.usersService.save({
        email: googleUser.email,
        nickname: googleUser.nickname,
        avatar: googleUser.avatar,
        active: true,
      });

      const tokens = await this.authService.createPairTokens(
        newUser.id,
        newUser.email,
      );

      const hashedRefreshToken = bcrypt.hashSync(
        tokens.refreshToken,
        this.saltRounds,
      );

      this.tokensService.save({
        userId: newUser.id,
        value: hashedRefreshToken,
        fingerprint,
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
    } else {
      if (user.password) {
        throw new ConflictException('🚨 user is already exist!');
      }
    }

    const tokens = await this.authService.createPairTokens(user.id, user.email);

    const hashedRefreshToken = bcrypt.hashSync(
      tokens.refreshToken,
      this.saltRounds,
    );

    this.tokensService.save({
      userId: user.id,
      value: hashedRefreshToken,
      fingerprint,
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
}
