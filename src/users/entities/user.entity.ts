import {
  Column,
  Entity,
  OneToMany,
  PrimaryGeneratedColumn,
  Relation,
} from 'typeorm';
import { BaseEntity } from '../../common/entities/base.entity.js';
import { Token } from '../../tokens/entities/token.entity.js';

const tableName = 'users';

@Entity({ name: tableName })
export class User extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column('varchar')
  email!: string;

  @Column({ default: null, type: 'varchar' })
  phone!: string | null;

  @Column('varchar')
  nickname!: string;

  @Column('varchar')
  password!: string;

  @Column({ type: 'bool', default: false })
  active!: boolean;

  @Column({ name: 'recovery_token', default: null, type: 'varchar' })
  recoveryToken!: string | null;

  @Column({ name: 'confirmation_token', default: null, type: 'varchar' })
  confirmationToken!: string | null;

  @OneToMany(() => Token, (token) => token.user)
  tokens!: Relation<Token[]>;
}
