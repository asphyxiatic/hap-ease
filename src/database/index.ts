import { DataSource } from 'typeorm';
import { User } from '../users/entities/user.entity.js';
import config from '../config/config.js';

export const appDataSource = new DataSource({
  type: 'postgres',
  url: config.DB_URL,
  entities: [User],
  migrations: ['./dist/src/database/migrations/*.js'],
  migrationsTableName: 'migrations_table',
});
