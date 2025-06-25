import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn, ManyToOne, OneToMany, JoinColumn } from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { PackageStatus } from './package-status.entity';

@Entity('packages')
export class PackageEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  trackingNumber: string;

  @Column()
  userId: string;

  @Column()
  agencyId: string;

  @Column()
  status: string;

  @Column({ type: 'date' })
  deliveryEstimate: string;

  @Column()
  origin: string;

  @Column()
  destination: string;

  @Column()
  carrier: string;

  @Column()
  assignedUserEmail: string;

  @ManyToOne(() => User, (user) => user.packages)
  @JoinColumn({ name: 'userId' })
  user: User;

  @OneToMany(() => PackageStatus, (status) => status.package, { cascade: true })
  statusHistory: PackageStatus[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}