import { Type } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class SignInDto {
  @IsEmail()
  @IsNotEmpty()
  email!: string;

  @Length(8, 25)
  @Type(() => String)
  @IsString()
  @IsNotEmpty()
  password!: string;
}
