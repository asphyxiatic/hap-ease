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

  @Column({
    type: 'varchar',
    default:
      'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQLzIeJzBVRDB4jmiqxlbFP17qBL84lX9hyAQ&usqp=CAU',
  })
  avatar!: string;

  @Column({ type: 'varchar', default: null })
  password!: string | null;

  @Column({ type: 'bool', default: false })
  active!: boolean;

  @Column({ name: 'recovery_token', default: null, type: 'varchar' })
  recoveryToken!: string | null;

  @Column({ name: 'confirmation_token', default: null, type: 'varchar' })
  confirmationToken!: string | null;

  @OneToMany(() => Token, (token) => token.user)
  tokens!: Relation<Token[]>;
}
