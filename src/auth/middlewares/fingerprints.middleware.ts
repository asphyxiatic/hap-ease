import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Response } from 'express';
import { EncryptionService } from '../../encryption/services/encryption.service.js';

@Injectable()
export class FingerprintsMiddleware implements NestMiddleware {
  constructor(private readonly encryptionService: EncryptionService) {}

  async use(req: any, res: Response, next: NextFunction) {
    const {
      'sec-ch-ua': secChUa,
      'sec-ch-ua-platform': secChUaPlatform,
      'user-agent': userAgent,
      'accept-language': acceptLanguage,
      'upgrade-insecure-requests': upgradeInsecureReq,
    } = req.headers;

    const fingerprintData = [
      secChUa,
      secChUaPlatform,
      userAgent,
      acceptLanguage,
      upgradeInsecureReq,
    ].join('|');

    const fingerprint = await this.encryptionService.encrypt(fingerprintData);

    req['fingerprint'] = fingerprint;

    next();
  }
}
