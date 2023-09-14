import {
  Column,
  Entity,
  OneToMany,
  PrimaryGeneratedColumn,
  Relation,
} from 'typeorm';
import { BaseEntity } from '../../common/entities/base.entity.js';
import { Token } from '../../tokens/entities/token.entity.js';
import config from '../../config/config.js';

const tableName = 'users';

@Entity({ name: tableName })
export class User extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column('varchar')
  email!: string;

  @Column({ type: 'varchar', nullable: true })
  phone?: string | null;

  @Column('varchar')
  nickname!: string;

  @Column({ type: 'varchar', default: config.DEFAULT_USER_AVATAR })
  avatar!: string;

  @Column({ type: 'varchar', nullable: true })
  password?: string;

  @Column({ type: 'boolean', default: false })
  active!: boolean;

  @Column({ name: '2fa-enabled', type: 'boolean', default: false })
  isTwoFactorAuthenticationEnabled!: boolean;

  @Column({ name: '2fa-secret', type: 'varchar', nullable: true })
  twoFactorAuthenticationSecret?: string | null;

  @Column({ name: '2fa-reservation-code', type: 'varchar', nullable: true })
  twoFactorReservationCode?: string | null;

  @Column({ name: 'recovery_token', type: 'varchar', nullable: true })
  recoveryToken?: string | null;

  @Column({ name: 'confirmation_token', type: 'varchar', nullable: true })
  confirmationToken?: string | null;

  @OneToMany(() => Token, (token) => token.user)
  tokens!: Relation<Token[]>;
}
