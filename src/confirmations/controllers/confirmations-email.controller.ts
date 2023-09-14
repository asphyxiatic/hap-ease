import { Controller, Patch, Post, UseGuards } from '@nestjs/common';
import { ConfirmationsEmailService } from '../services/confirmations-email.service.js';
import { IUserRequest } from '../../common/interfaces/user-request.interface.js';
import { GetCurrentUser } from '../../common/decorators/get-current-user.js';
import { GetToken } from '../../auth/decorators/get-auth-token.decorator.js';
import { ConfirmationTokenGuard } from '../guards/confirmation-token.guard.js';

@Controller()
export class ConfirmationsEmailController {
  constructor(
    private readonly confirmationsEmailService: ConfirmationsEmailService,
  ) {}

  @Post('email-confirmation-request')
  async emailConfirmationRequest(
    @GetCurrentUser() { email }: IUserRequest,
  ): Promise<void> {
    return this.confirmationsEmailService.emailConfirmationRequest(email);
  }

  @Patch('confirmation-email')
  @UseGuards(ConfirmationTokenGuard)
  async confirmationEmail(
    @GetToken('ct') confirmationToken: string,
    @GetCurrentUser() { userId }: IUserRequest,
  ): Promise<void> {
    return this.confirmationsEmailService.confirmationEmail(
      confirmationToken,
      userId,
    );
  }
}
