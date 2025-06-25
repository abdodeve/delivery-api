import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PackagesService } from './packages.service';
import { PackagesController } from './packages.controller';
import { PackageEntity } from './entities/package.entity';
import { PackageStatus } from './entities/package-status.entity';

@Module({
  imports: [TypeOrmModule.forFeature([PackageEntity, PackageStatus])],
  controllers: [PackagesController],
  providers: [PackagesService],
})
export class PackagesModule {}