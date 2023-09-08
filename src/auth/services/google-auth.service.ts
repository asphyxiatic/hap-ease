import { ConflictException, Injectable } from '@nestjs/common';
import { UsersService } from '../../users/services/users.service.js';
import { GoogleSignInResponseDto } from '../dto/google-sign-in-response.dto.js';
import { IUserRequestParams } from '../../common/interfaces/user-request-params.interface.js';

@Injectable()
export class GoogleOAuthService {
  constructor(private readonly usersService: UsersService) {}

  public async googleSignIn(
    googleUser: IUserRequestParams,
  ): Promise<GoogleSignInResponseDto> {
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
    }

    if (!user!.isRegisteredWithGoogle) {
      throw new ConflictException('🚨 user is already exist!');
    }

    const response = {
      user: {
        email: googleUser.email,
        nickname: googleUser.nickname!,
        avatar: googleUser.avatarUrl!,
      },
      access_token: googleUser.accessToken!,
      refresh_token: googleUser.refreshToken!,
    };

    return response;
  }
}
