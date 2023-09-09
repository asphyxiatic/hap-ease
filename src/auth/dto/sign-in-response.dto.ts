import { TokensResponse } from '../../common/dto/tokens-response.dto.js';
import { IUserData } from '../../common/interfaces/user-data.interface.js';

export class SignInResponseDto extends TokensResponse {
  user!: IUserData;
}
