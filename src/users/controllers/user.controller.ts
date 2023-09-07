import { Controller, Patch, Post, UseGuards } from '@nestjs/common';
import { GetAuthToken } from '../../auth/decorators/get-auth-token.decorator.js';
import { UsersService } from '../services/user.service.js';
import { AuthAccessGuard } from '../../auth/guards/auth-access.guard.js';
import { GetCurrentUser } from '../../common/decorators/get-current-user.decorators.js';
import { IUserRequestParams } from '../../common/interfaces/user-request-params.interface.js';

@Controller()
export class UserController {
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
  async confirmationEmail(
    @GetAuthToken() confirmationToken: string,
  ): Promise<void> {
    return this.userService.confirmationEmail(confirmationToken);
  }
}
