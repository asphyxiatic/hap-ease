import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { FindOptionsWhere, Repository } from 'typeorm';
import { User } from '../entities/user.entity.js';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  // -------------------------------------------------------------
  public async findOneFor(
    findOptions: FindOptionsWhere<User>,
  ): Promise<User | null> {
    const user = await this.userRepository.findOne({ where: findOptions });
    return user;
  }

  // -------------------------------------------------------------
  public async save(userOptions: Partial<User>): Promise<User> {
    try {
      return this.userRepository.save(userOptions);
    } catch (error: any) {
      throw new InternalServerErrorException('🚨 ' + error.message);
    }
  }

  // -------------------------------------------------------------
  public async turnOnTwoFactorAuth(userId: string): Promise<void> {
    await this.save({ id: userId, isTwoFactorAuthenticationEnabled: true });
  }

  // -------------------------------------------------------------
  public async turnOffTwoFactorAuth(userId: string): Promise<void> {
    await this.save({ id: userId, isTwoFactorAuthenticationEnabled: false });
  }
}
