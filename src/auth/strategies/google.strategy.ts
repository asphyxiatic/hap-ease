import { PassportStrategy } from '@nestjs/passport';
import {
  Strategy,
  StrategyOptions,
} from 'passport-google-oauth20';
import config from '../../config/config.js';
import { Injectable } from '@nestjs/common';
import { IUserRequestParams } from '../../common/interfaces/user-request-params.interface.js';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor() {
    super({
      clientID: config.GOOGLE_AUTH_CLIENT_ID,
      clientSecret: config.GOOGLE_AUTH_CLIENT_SECRET,
      callbackURL: 'http://localhost:3001/google-auth',
      scope: ['email', 'profile'],
    } as StrategyOptions);
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
  ): Promise<any> {
    const { name, emails, photos } = profile;

    const user = {
      email: emails[0].value,
      nickname: name.givenName + ' ' + name.familyName,
      avatarUrl: photos[0].value,
      accessToken,
      refreshToken,
    };

    return user;
  }
}
