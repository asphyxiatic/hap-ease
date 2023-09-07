import { InjectRepository } from '@nestjs/typeorm';
import { Token } from '../entities/token.entity.js';
import { FindOptionsWhere, Repository } from 'typeorm';
import { InternalServerErrorException } from '@nestjs/common';

export class TokensService {
  constructor(
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
  ) {}

  public async save(tokenOptions: Partial<Token>): Promise<Token> {
    return this.tokenRepository.save(tokenOptions);
  }

  public async find(tokenOptions: FindOptionsWhere<Token>): Promise<Token[]> {
    return this.tokenRepository.find({ where: tokenOptions });
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
