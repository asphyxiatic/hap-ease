import { InjectRepository } from '@nestjs/typeorm';
import { Token } from '../entities/token.entity.js';
import { FindOptionsWhere, Repository } from 'typeorm';
import { InternalServerErrorException } from '@nestjs/common';

export class TokensService {
  constructor(
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
  ) {}

  public async save(
    tokenOptions: Partial<Token> & { fingerprint: string },
  ): Promise<Token> {
    const tokenForfingerprint = await this.findOne({
      fingerprint: tokenOptions.fingerprint,
    });

    if (!tokenForfingerprint) {
      return this.tokenRepository.save(tokenOptions);
    } else {
      return this.tokenRepository.save({
        ...tokenOptions,
        id: tokenForfingerprint.id,
      });
    }
  }

  public async find(tokenOptions: FindOptionsWhere<Token>): Promise<Token[]> {
    return this.tokenRepository.find({ where: tokenOptions });
  }

  public async findOne(
    tokenOptions: FindOptionsWhere<Token>,
  ): Promise<Token | null> {
    return this.tokenRepository.findOne({ where: tokenOptions });
  }

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
