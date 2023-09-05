import { InjectRepository } from '@nestjs/typeorm';
import { Token } from '../entities/token.entity.js';
import { FindOptionsWhere, Repository } from 'typeorm';

export class TokensService {
  constructor(
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
  ) {}

  public async save(tokenOptions: Partial<Token>): Promise<Token> {
    return this.tokenRepository.save(tokenOptions);
  }

  public async find(
    tokenOptions:
      | FindOptionsWhere<Token>
      | FindOptionsWhere<Token>[]
      | undefined,
  ): Promise<Token[]> {
    return this.tokenRepository.find({ where: tokenOptions });
  }
}
