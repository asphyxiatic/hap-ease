import { ExecutionContext, createParamDecorator } from '@nestjs/common';

export const GetConfirmationToken = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();

    const confirmationToken = request.headers['confirmation-token'];

    return confirmationToken;
  },
);
