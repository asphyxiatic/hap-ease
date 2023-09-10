import { InjectRepository } from '@nestjs/typeorm';
import { Token } from '../entities/token.entity.js';
import { FindOptionsWhere, Repository } from 'typeorm';
import { InternalServerErrorException } from '@nestjs/common';
import { EncryptionService } from '../../encryption/services/encryption.service.js';
import * as bcrypt from 'bcrypt';

export class TokensService {
  private readonly saltRounds = 5;

  constructor(
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
    private readonly encryptionService: EncryptionService,
  ) {}

  // -------------------------------------------------------------
  public async save(
    tokenOptions: Partial<Token> & {
      fingerprint: string;
      value: string;
      userId: string;
    },
  ): Promise<Token> {
    const encryptToken = await this.encryptionService.encrypt(
      tokenOptions.value,
    );

    const hashedToken = bcrypt.hashSync(encryptToken, this.saltRounds);

    const tokenForfingerprint = await this.findOne({
      fingerprint: tokenOptions.fingerprint,
    });

    if (!tokenForfingerprint) {
      return this.tokenRepository.save({
        ...tokenOptions,
        value: hashedToken,
      });
    } else {
      return this.tokenRepository.save({
        ...tokenOptions,
        value: hashedToken,
        id: tokenForfingerprint.id,
      });
    }
  }

  // -------------------------------------------------------------
  public async find(tokenOptions: FindOptionsWhere<Token>): Promise<Token[]> {
    return this.tokenRepository.find({ where: tokenOptions });
  }

  // -------------------------------------------------------------
  public async findOne(
    tokenOptions: FindOptionsWhere<Token>,
  ): Promise<Token | null> {
    return this.tokenRepository.findOne({ where: tokenOptions });
  }

  // -------------------------------------------------------------
  public async delete(value: string): Promise<void> {
    try {
      this.tokenRepository.delete({
        value: value,
      });
    } catch (error) {
      throw new InternalServerErrorException('🚨 failed to log-out!');
    }
  }
}
