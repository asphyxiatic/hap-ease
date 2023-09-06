import { JwtService } from '@nestjs/jwt';
import { ITokenPayload } from '../../common/interfaces/token-payload.interface.js';
import { IDecodeTokenResponse } from '../interfaces/decode-token-response.interface.js';
import { Injectable, InternalServerErrorException } from '@nestjs/common';

@Injectable()
export class JwtToolsService {
  constructor(private readonly jwtService: JwtService) {}

  public async createToken(
    payload: ITokenPayload,
    secret: string,
    expires: string,
  ): Promise<string> {
    const token = await this.jwtService.signAsync(payload, {
      secret: secret,
      expiresIn: expires,
    });
    return token;
  }

  // -------------------------------------------------------------
  public async decodeToken(
    token: string,
    secret: string,
  ): Promise<IDecodeTokenResponse> {
    const decodeToken: ITokenPayload = await this.jwtService
      .verifyAsync(token, { secret: secret })
      .catch((error: any) => {
        throw new InternalServerErrorException('🚨 token is invalid!');
      });

    return {
      userId: decodeToken.sub,
      email: decodeToken.email,
    };
  }
}
