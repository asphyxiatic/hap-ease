import { Body, Controller, Patch, Post, UseGuards } from '@nestjs/common';
import { UsersService } from '../services/users.service.js';
import { GetCurrentUser } from '../../common/decorators/get-current-user.js';
import { ConfirmationTokenGuard } from '../guards/confirmation-token.guard.js';
import { GetToken } from '../../auth/decorators/get-auth-token.decorator.js';
import { IUserRequest } from '../../common/interfaces/user-request.interface.js';
import { ChangePasswordDto } from '../dto/change-password.dto.js';

@Controller('users')
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Post('email-confirmation-request')
  async emailConfirmationRequest(
    @GetCurrentUser() { email }: IUserRequest,
  ): Promise<void> {
    return this.userService.emailConfirmationRequest(email);
  }

  @Patch('confirmation-email')
  @UseGuards(ConfirmationTokenGuard)
  async confirmationEmail(
    @GetToken('ct') confirmationToken: string,
    @GetCurrentUser() { userId }: IUserRequest,
  ): Promise<void> {
    return this.userService.confirmationEmail(confirmationToken, userId);
  }

  @Patch('change-password')
  async changePassword(
    @Body() { newPassword, code }: ChangePasswordDto,
    @GetCurrentUser() { userId }: IUserRequest,
  ): Promise<void> {
    return this.userService.changePassword(newPassword, code, userId);
  }
}
