import { Injectable } from '@nestjs/common';
import { PassportSerializer } from '@nestjs/passport';
import { UsersService } from '../../users/services/users.service.js';
import { User } from '../../users/entities/user.entity.js';

@Injectable()
export class SessionSerializer extends PassportSerializer {
  constructor(private readonly userService: UsersService) {
    super();
  }

  async serializeUser(user: User, done: Function): Promise<any> {
    console.log('Serializer User');
    done(null, user);
  }

  async deserializeUser(payload: any, done: Function): Promise<any> {
    const user = await this.userService.findOneFor({ id: payload.id });
    console.log(`Deserialize User: ${user}`);
    return user ? done(null, user) : done(null, null);
  }
}
