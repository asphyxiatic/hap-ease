import { ExecutionContext, createParamDecorator } from '@nestjs/common';
import { IGetToken } from '../interfaces/get-token.interface.js';

export const GetToken = createParamDecorator(
  (data: keyof IGetToken, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();

    const headers = request.headers;

    if (
      data === 'at' ||
      data === 'rt' ||
      data === 'rect' ||
      typeof data === 'undefined'
    ) {
      const [type, token] = headers.authorization.split(' ');
      return type === 'Bearer' ? token : undefined;
    } else if (data === 'gt') {
      const googleToken = headers.authorization;

      return googleToken;
    } else if (data === 'ct') {
      const confirmationToken = headers['confirmation-token'];

      return confirmationToken;
    }
  },
);
