import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { Repository } from 'typeorm';
import { User } from '../../users/entities/user.entity.js';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { SignUpDto } from '../dto/sign-up.dto.js';
import { SignInDto } from '../dto/sign-in.dto.js';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async signUp({ email, nickname, password }: SignUpDto): Promise<User> {
    const existingUser = await this.userRepository.findOne({
      where: {
        email: email,
      },
    });

    if (existingUser) {
      throw new UnauthorizedException('Email is already exist');
    }

    const hashedPassword = await bcrypt.hashSync(password, 5);

    return this.userRepository.save({
      email: email,
      nickname: nickname,
      password: hashedPassword,
    });
  }

  async signIn({ email, password }: SignInDto): Promise<User> {
    const user = await this.userRepository.findOne({ where: { email: email } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const passwordIsValid = await bcrypt.compareSync(password, user.password);

    if (!passwordIsValid) {
      throw new UnauthorizedException('Incorrect password');
    }

    return user;
  }
}
