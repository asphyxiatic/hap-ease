import { Type } from 'class-transformer';
import { IsNotEmpty, IsOptional, IsString, Length } from 'class-validator';

export class UpdatePasswordDto {
  @Length(8, 25)
  @Type(() => String)
  @IsString()
  @IsNotEmpty()
  password!: string;

  @Length(6)
  @Type(() => String)
  @IsString()
  @IsOptional()
  code?: string | undefined;
}
