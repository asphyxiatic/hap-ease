import { Type } from 'class-transformer';
import { IsNotEmpty, IsString, Length } from 'class-validator';

export class UpdatePasswordDto {
  @Length(8, 25)
  @Type(() => String)
  @IsString()
  @IsNotEmpty()
  password!: string;
}
