import { Controller, Patch, Post, UseGuards } from '@nestjs/common';
import { UsersService } from '../services/users.service.js';
import { GetCurrentUser } from '../../common/decorators/get-current-user.js';
import { ConfirmationTokenGuard } from '../guards/confirmation-token.guard.js';
import { GetToken } from '../../auth/decorators/get-auth-token.decorator.js';
import { IUserRequest } from '../../common/interfaces/user-request.interface.js';

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
    @GetCurrentUser() { email }: IUserRequest,
  ): Promise<void> {
    return this.userService.confirmationEmail(confirmationToken, email);
  }
}
