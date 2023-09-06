import { Controller, Patch, Post } from '@nestjs/common';
import { GetAuthToken } from '../../auth/decorators/get-auth-token.decorator.js';
import { UsersService } from '../services/user.service.js';

@Controller()
export class UserController {
  constructor(private readonly userService: UsersService) {}

  @Post('email-confirmation-request')
  // Нужно добавить декоратор для получения текущего пользователя "GetCurrentUser"
  async emailConfirmationRequest(userId: string): Promise<void> {
    return this.userService.emailConfirmationRequest(userId);
  }

  @Patch('confirmation-email')
  async confirmationEmail(
    @GetAuthToken() confirmationToken: string,
  ): Promise<void> {
    return this.userService.confirmationEmail(confirmationToken);
  }
}
