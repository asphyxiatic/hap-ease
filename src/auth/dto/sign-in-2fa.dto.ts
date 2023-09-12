import { Type } from 'class-transformer';
import { IsNotEmpty, IsString, Length } from 'class-validator';

export class SignIn2FADto {
  @Length(6)
  @Type(() => String)
  @IsString()
  @IsNotEmpty()
  code!: string;
}
