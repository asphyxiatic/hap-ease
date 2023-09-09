import {
  Column,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  Relation,
  Unique,
} from 'typeorm';
import { User } from '../../users/entities/user.entity.js';

const tableName = 'tokens';

@Entity({ name: tableName })
export class Token {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column('varchar')
  value!: string;

  @Column({ name: 'user_id', type: 'uuid' })
  userId!: User['id'];

  @Column({ name: 'fingerprint', unique: true, type: 'varchar', default: null })
  fingerprint!: string | null;

  @ManyToOne(() => User, (user) => user.tokens, {
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
  })
  @JoinColumn({ name: 'user_id' })
  user!: Relation<User>;
}
