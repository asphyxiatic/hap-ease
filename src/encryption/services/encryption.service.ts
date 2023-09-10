import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

@Injectable()
export class EncryptionService {
  public async encrypt(data: string): Promise<string> {
    return crypto.createHash('md5').update(data).digest('hex');
  }
}
