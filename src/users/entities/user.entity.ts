import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { BaseEntity } from '../../common/entities/base.entity.js';

@Entity({ name: 'user' })
export class User extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column('varchar')
  email!: string;

  @Column('varchar')
  phone!: string;

  @Column('varchar')
  nickname!: string;

  @Column('varchar')
  password!: string;
}
