import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Response } from 'express';
import * as crypto from 'crypto';

@Injectable()
export class FingerprintsMiddleware implements NestMiddleware {
  use(req: any, res: Response, next: NextFunction) {
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

    const fingerprint = crypto
      .createHash('md5')
      .update(fingerprintData)
      .digest('hex');

    req['fingerprint'] = fingerprint;

    next();
  }
}
