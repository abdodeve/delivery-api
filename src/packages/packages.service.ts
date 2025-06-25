import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PackageEntity } from './entities/package.entity';
import { PackageStatus } from './entities/package-status.entity';
import { CreatePackageDto } from './dto/create-package.dto';
import { UpdatePackageDto } from './dto/update-package.dto';
import { User } from '../users/entities/user.entity';
import { Role } from '../common/enums/role.enum';

@Injectable()
export class PackagesService {
  constructor(
    @InjectRepository(PackageEntity)
    private readonly packageRepository: Repository<PackageEntity>,
    @InjectRepository(PackageStatus)
    private readonly packageStatusRepository: Repository<PackageStatus>,
  ) {}

  async create(createPackageDto: CreatePackageDto): Promise<PackageEntity> {
    const packageEntity = this.packageRepository.create(createPackageDto);
    const savedPackage = await this.packageRepository.save(packageEntity);

    // Create initial status
    const initialStatus = this.packageStatusRepository.create({
      status: createPackageDto.status,
      timestamp: new Date(),
      location: createPackageDto.origin,
      packageId: savedPackage.id,
    });
    await this.packageStatusRepository.save(initialStatus);

    return savedPackage;
  }

  async findAll(user: User): Promise<PackageEntity[]> {
    if (user.role === Role.ADMIN) {
      return this.packageRepository.find({
        relations: ['user', 'statusHistory'],
        order: { createdAt: 'DESC' },
      });
    }

    return this.packageRepository.find({
      where: { userId: user.id },
      relations: ['statusHistory'],
      order: { createdAt: 'DESC' },
    });
  }

  async findOne(id: string, user: User): Promise<PackageEntity> {
    const packageEntity = await this.packageRepository.findOne({
      where: { id },
      relations: ['user', 'statusHistory'],
    });

    if (!packageEntity) {
      throw new NotFoundException('Package not found');
    }

    // Users can only view their own packages, admins can view all
    if (user.role !== Role.ADMIN && packageEntity.userId !== user.id) {
      throw new ForbiddenException('Access denied');
    }

    return packageEntity;
  }

  async update(id: string, updatePackageDto: UpdatePackageDto, user: User): Promise<PackageEntity> {
    const packageEntity = await this.findOne(id, user);

    // Only admins can update packages
    if (user.role !== Role.ADMIN) {
      throw new ForbiddenException('Only admins can update packages');
    }

    await this.packageRepository.update(id, updatePackageDto);
    
    // If status is updated, add to status history
    if (updatePackageDto.status) {
      const statusUpdate = this.packageStatusRepository.create({
        status: updatePackageDto.status,
        timestamp: new Date(),
        location: updatePackageDto.origin || packageEntity.origin,
        packageId: id,
      });
      await this.packageStatusRepository.save(statusUpdate);
    }

    return this.findOne(id, user);
  }

  async remove(id: string, user: User): Promise<void> {
    const packageEntity = await this.findOne(id, user);

    // Only admins can delete packages
    if (user.role !== Role.ADMIN) {
      throw new ForbiddenException('Only admins can delete packages');
    }

    await this.packageRepository.remove(packageEntity);
  }

  async getPackageStatus(id: string, user: User): Promise<PackageStatus[]> {
    const packageEntity = await this.findOne(id, user);
    
    return this.packageStatusRepository.find({
      where: { packageId: packageEntity.id },
      order: { timestamp: 'ASC' },
    });
  }
}