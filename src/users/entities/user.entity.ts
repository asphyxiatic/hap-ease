import { Column, Entity, OneToMany, PrimaryGeneratedColumn, Relation } from 'typeorm';
import { BaseEntity } from '../../common/entities/base.entity.js';
import { Tokens } from '../../auth/entities/token.entity.js';

const tableName = 'user';

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

  @OneToMany(() => Tokens, (token) => token.user)
  tokens!: Relation<Tokens[]>;
}
