import { Type } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class SignUpDto {
  @IsEmail()
  @IsNotEmpty()
  email!: string;

  @Type(() => String)
  @IsString()
  @IsNotEmpty()
  nickname!: string;

  @Length(8, 25)
  @Type(() => String)
  @IsString()
  @IsNotEmpty()
  password!: string;
}
