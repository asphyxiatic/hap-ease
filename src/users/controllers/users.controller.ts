import { Controller, Patch, Post, UseGuards } from '@nestjs/common';
import { UsersService } from '../services/users.service.js';
import { AuthAccessGuard } from '../../auth/guards/auth-access.guard.js';
import { GetCurrentUser } from '../../common/decorators/get-current-user.decorators.js';
import { IUserRequestParams } from '../../common/interfaces/user-request-params.interface.js';
import { GetConfirmationToken } from '../decorators/get-confirmation-token.decorator.js';
import { NotEmptyConfirmationTokenGuard } from '../guards/not-empty-confirmation-token.guard.js';

@Controller('users')
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Post('email-confirmation-request')
  @UseGuards(AuthAccessGuard)
  async emailConfirmationRequest(
    @GetCurrentUser() { userId }: IUserRequestParams,
  ): Promise<void> {
    return this.userService.emailConfirmationRequest(userId);
  }

  @Patch('confirmation-email')
  @UseGuards(AuthAccessGuard)
  @UseGuards(NotEmptyConfirmationTokenGuard)
  async confirmationEmail(
    @GetConfirmationToken() confirmationToken: string,
  ): Promise<void> {
    return this.userService.confirmationEmail(confirmationToken);
  }
}
