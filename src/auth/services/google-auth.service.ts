import { Injectable, UnauthorizedException } from '@nestjs/common';
import { google, Auth } from 'googleapis';
import config from '../../config/config.js';
import { UsersService } from '../../users/services/users.service.js';
import { User } from '../../users/entities/user.entity.js';

@Injectable()
export class GoogleAuthService {
  private readonly oauthGoogleClient: Auth.OAuth2Client;
  private readonly GOOGLE_AUTH_CLIENT_ID = config.GOOGLE_AUTH_CLIENT_ID;
  private readonly GOOGLE_AUTH_CLIENT_SECRET = config.GOOGLE_AUTH_CLIENT_SECRET;

  constructor(private readonly userService: UsersService) {
    this.oauthGoogleClient = new google.auth.OAuth2({
      clientId: this.GOOGLE_AUTH_CLIENT_ID,
      clientSecret: this.GOOGLE_AUTH_CLIENT_SECRET,
    });
  }

  // -------------------------------------------------------------
  public async authenticate(token: string): Promise<User> {
    const userInfo = await this.getUserData(token);

    console.log(userInfo);

    const userOptions = {
      email: userInfo.email!,
      nickname: userInfo.name!,
    };

    const user = await this.userService.findOneFor(userOptions);

    if (!user) {
      const newUser = await this.userService.save({
        ...userOptions,
        isRegisteredWithGoogle: true,
        active: true,
      });

      return newUser;
    }

    return user;
  }

  // -------------------------------------------------------------
  private async getUserData(token: string): Promise<any> {
    try {
      const userInfoClient = google.oauth2('v2').userinfo;

      this.oauthGoogleClient.setCredentials({
        access_token: token,
      });

      const userInfoResponse = await userInfoClient.get({
        auth: this.oauthGoogleClient,
      });

      return userInfoResponse.data;
    } catch (error: any) {
      throw new UnauthorizedException('🚨 google authentication error!');
    }
  }
}
