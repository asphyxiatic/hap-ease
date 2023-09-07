import { ExecutionContext, createParamDecorator } from '@nestjs/common';
import { Request } from 'express';

export const GetAuthToken = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request: Request = ctx.switchToHttp().getRequest();
    const authorization = request.headers.authorization;

    const [type, refreshToken] = authorization!.split(' ');

    return type === 'Bearer' ? refreshToken : undefined;
  },
);
