import { cleanEnv, num, str } from 'envalid';
import * as dotenv from 'dotenv';

dotenv.config();

export default cleanEnv(process.env, {
  DB_URL: str(),
  APP_PORT: num({ default: 3000 }),
});
