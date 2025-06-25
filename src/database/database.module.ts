import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SeedingService } from './seeding.service';
import { User } from '../users/entities/user.entity';
import { PackageEntity } from '../packages/entities/package.entity';
import { PackageStatus } from '../packages/entities/package-status.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User, PackageEntity, PackageStatus])],
  providers: [SeedingService],
  exports: [SeedingService],
})
export class DatabaseModule {}