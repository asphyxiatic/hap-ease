export class GoogleSignInResponseDto {
  user!: {
    email: string;
    nickname: string;
    avatar: string;
  };

  access_token!: string;
  refresh_token!: string;
}
