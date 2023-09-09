import { IUserData } from './user-data.interface.js';

export interface IUserRequest extends IUserData {
  userId: string;
}
