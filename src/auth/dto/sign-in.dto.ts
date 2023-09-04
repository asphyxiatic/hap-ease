import { Type } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class SignInDto {
  @Type(() => String)
  @IsString()
  @IsNotEmpty()
  @IsEmail()
  email!: string;

  @Type(() => String)
  @IsString()
  @IsNotEmpty()
  password!: string;
}
