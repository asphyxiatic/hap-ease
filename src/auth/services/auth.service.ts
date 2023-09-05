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
import { JwtService } from '@nestjs/jwt';
import { Tokens } from '../entities/token.entity.js';
import config from '../../config/config.js';
import { randomUUID } from 'crypto';
import { SignUpResponseDto } from '../dto/sign-up-response.dto.js';
import { SignInResponseDto } from '../dto/sign-in-response.dto.js';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Tokens)
    private readonly tokenRepository: Repository<Tokens>,
    private readonly jwtService: JwtService,
  ) {}

  // -------------------------------------------------------------
  async createTokens(userId: string, email: string) {
    const payload = { sub: userId, email: email };

    const accessToken = await this.jwtService.signAsync(
      { unique: randomUUID(), ...payload },
      {
        secret: config.JWT_ACCESS_SECRET_KEY,
        expiresIn: '5m',
      },
    );

    const refreshToken = await this.jwtService.signAsync(
      { unique: randomUUID(), ...payload },
      {
        secret: config.JWT_REFRESH_SECRET_KEY,
        expiresIn: '60d',
      },
    );

    const hashedRefreshToken = await bcrypt.hashSync(refreshToken, 5);

    this.tokenRepository.save({
      userId: userId,
      value: hashedRefreshToken,
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  // -------------------------------------------------------------
  async signUp({
    email,
    nickname,
    password,
  }: SignUpDto): Promise<SignUpResponseDto> {
    const existingUser = await this.userRepository.findOne({
      where: {
        email: email,
      },
    });

    if (existingUser) {
      throw new UnauthorizedException('User is already exist');
    }

    const hashedPassword = await bcrypt.hashSync(password, 5);

    const newUserProps: Partial<User> = {
      email: email,
      nickname: nickname,
      password: hashedPassword,
    };

    const newUser = await this.userRepository.save(newUserProps);

    const tokens = await this.createTokens(newUser.id, newUser.email);

    return tokens;
  }

  // -------------------------------------------------------------
  async signIn({ email, password }: SignInDto): Promise<SignInResponseDto> {
    const user = await this.userRepository.findOne({ where: { email: email } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const passwordIsValid = await bcrypt.compareSync(password, user.password);

    if (!passwordIsValid) {
      throw new UnauthorizedException('Incorrect password');
    }

    const tokens = await this.createTokens(user.id, user.email);

    return tokens;
  }
}
