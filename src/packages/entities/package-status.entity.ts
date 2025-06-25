import { Entity, Column, PrimaryGeneratedColumn, ManyToOne, JoinColumn } from 'typeorm';
import { PackageEntity } from './package.entity';

@Entity('package_status')
export class PackageStatus {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  status: string;

  @Column({ type: 'timestamp' })
  timestamp: Date;

  @Column()
  location: string;

  @Column()
  packageId: string;

  @ManyToOne(() => PackageEntity, (pkg) => pkg.statusHistory)
  @JoinColumn({ name: 'packageId' })
  package: PackageEntity;
}