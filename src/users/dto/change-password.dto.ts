import { Type } from 'class-transformer';
import { IsNotEmpty, IsString, Length } from 'class-validator';

export class ChangePasswordDto {
  @Length(8, 25)
  @Type(() => String)
  @IsString()
  @IsNotEmpty()
  newPassword!: string;

  @Length(6)
  @Type(() => String)
  @IsString()
  code?: string | undefined;
}
