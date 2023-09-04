import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { BaseEntity } from '../../common/entities/base.entity.js';

@Entity({ name: 'user' })
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
}
