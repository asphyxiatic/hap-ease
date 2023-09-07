import { ExecutionContext, createParamDecorator } from '@nestjs/common';
import { IUserRequestParams } from '../interfaces/user-request-params.interface.js';

export const GetCurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): IUserRequestParams => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user as IUserRequestParams;
    return user;
  },
);
