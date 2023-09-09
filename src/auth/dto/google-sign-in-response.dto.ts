import { TokensResponse } from '../../common/dto/tokens-response.dto.js';
import { IUserData } from '../../common/interfaces/user-data.interface.js';

export class GoogleSignInResponseDto extends TokensResponse {
  user!: IUserData;
}
