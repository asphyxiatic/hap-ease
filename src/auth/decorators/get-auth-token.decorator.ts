import {
  ExecutionContext,
  NotFoundException,
  createParamDecorator,
} from '@nestjs/common';
import { Request } from 'express';

export const GetAuthToken = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request: Request = ctx.switchToHttp().getRequest();
    const authorization = request.headers.authorization;

    if (!authorization) {
      throw new NotFoundException('🚨 refresh-token not found');
    }

    const [type, refreshToken] = authorization.split(' ');

    return type === 'Bearer' ? refreshToken : undefined;
  },
);
