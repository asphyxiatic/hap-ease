import { cleanEnv, num, str } from 'envalid';
import * as dotenv from 'dotenv';

dotenv.config();

export default cleanEnv(process.env, {
  DB_URL: str(),
  APP_PORT: num({ default: 3000 }),
  JWT_ACCESS_SECRET_KEY: str(),
  JWT_REFRESH_SECRET_KEY: str(),
  JWT_RECOVERY_SECRET_KEY: str(),
  JWT_CONFIRMATION_SECRET_KEY: str(),
  MAIL_TRANSPORT: str(),
  MAIL_FROM_NAME: str(),
  GOOGLE_AUTH_CLIENT_ID: str(),
  GOOGLE_AUTH_CLIENT_SECRET: str(),
  SESSION_SECRET: str(),
});
