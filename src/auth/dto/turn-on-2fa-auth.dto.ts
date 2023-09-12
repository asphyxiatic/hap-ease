import { Type } from 'class-transformer';
import { IsNotEmpty, IsString, Length } from 'class-validator';

export class TurnOnTwoFactorAuthDto {
  @Length(6)
  @Type(() => String)
  @IsString()
  @IsNotEmpty()
  code!: string;
}
