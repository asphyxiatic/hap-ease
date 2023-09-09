import { ITokens } from './tokens.interface.js';
import { IUserData } from '../../common/interfaces/user-data.interface.js';

export interface IGoogleUser extends IUserData, ITokens {}
