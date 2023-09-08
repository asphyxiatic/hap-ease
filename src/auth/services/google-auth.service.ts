import { ConflictException, Injectable } from '@nestjs/common';
import { UsersService } from '../../users/services/users.service.js';
import { IUserRequestParams } from '../../common/interfaces/user-request-params.interface.js';
import { IGoogleUser } from '../interfaces/google-user.interface.js';

@Injectable()
export class GoogleOAuthService {
  constructor(private readonly usersService: UsersService) {}

  // -------------------------------------------------------------
  public async googleSignIn(
    googleUser: IGoogleUser,
  ): Promise<IUserRequestParams> {
    const user = await this.usersService.findOneFor({
      email: googleUser.email,
    });

    if (!user) {
      const newUser = await this.usersService.save({
        email: googleUser.email,
        nickname: googleUser.nickname,
        isRegisteredWithGoogle: true,
        avatar: googleUser.avatarUrl,
        active: true,
      });

      return {
        userId: newUser.id,
        email: newUser.email,
        nickname: newUser.nickname,
        avatarUrl: newUser.avatar,
        accessToken: googleUser.accessToken,
        refreshToken: googleUser.refreshToken,
      };
    } else {
      if (!user.isRegisteredWithGoogle) {
        throw new ConflictException('🚨 user is already exist!');
      }
    }

    return {
      ...googleUser,
      userId: user.id,
    };
  }
}
