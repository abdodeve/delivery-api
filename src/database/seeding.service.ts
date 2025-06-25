import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from '../users/entities/user.entity';
import { PackageEntity } from '../packages/entities/package.entity';
import { PackageStatus } from '../packages/entities/package-status.entity';
import { Role } from '../common/enums/role.enum';

@Injectable()
export class SeedingService {
  private readonly logger = new Logger(SeedingService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(PackageEntity)
    private readonly packageRepository: Repository<PackageEntity>,
    @InjectRepository(PackageStatus)
    private readonly packageStatusRepository: Repository<PackageStatus>,
  ) {}

  async seedAll(): Promise<void> {
    try {
      this.logger.log('Starting database seeding...');
      
      // Check if data already exists
      const userCount = await this.userRepository.count();
      if (userCount > 0) {
        this.logger.log('Database already seeded, skipping...');
        return;
      }

      await this.seedUsers();
      await this.seedPackages();
      await this.seedPackageStatuses();
      
      this.logger.log('Database seeding completed successfully!');
    } catch (error) {
      this.logger.error('Error seeding database:', error);
      throw error;
    }
  }

  private async seedUsers(): Promise<void> {
    this.logger.log('Seeding users...');

    const users = [
      {
        email: 'admin@example.com',
        password: await bcrypt.hash('admin123', 10),
        role: Role.ADMIN,
      },
      {
        email: 'user@example.com',
        password: await bcrypt.hash('user123', 10),
        role: Role.USER,
      },
      {
        email: 'john@example.com',
        password: await bcrypt.hash('john123', 10),
        role: Role.USER,
      },
    ];

    for (const userData of users) {
      const user = this.userRepository.create(userData);
      await this.userRepository.save(user);
      this.logger.log(`Created user: ${userData.email}`);
    }
  }

  private async seedPackages(): Promise<void> {
    this.logger.log('Seeding packages...');

    // Get the user to assign packages to
    const user = await this.userRepository.findOne({
      where: { email: 'user@example.com' },
    });

    if (!user) {
      throw new Error('User not found for package seeding');
    }

    const packages = [
      {
        trackingNumber: 'TRK001234567',
        userId: user.id,
        agencyId: 'agency1',
        status: 'In Transit',
        deliveryEstimate: '2025-06-15',
        origin: 'New York, NY',
        destination: 'Los Angeles, CA',
        carrier: 'Express Delivery',
        assignedUserEmail: 'john@example.com',
      },
      {
        trackingNumber: 'TRK001234568',
        userId: user.id,
        agencyId: 'agency1',
        status: 'Delivered',
        deliveryEstimate: '2025-06-10',
        origin: 'Chicago, IL',
        destination: 'Miami, FL',
        carrier: 'Express Delivery',
        assignedUserEmail: 'john@example.com',
      },
      {
        trackingNumber: 'TRK001234569',
        userId: user.id,
        agencyId: 'agency1',
        status: 'Created',
        deliveryEstimate: '2025-06-18',
        origin: 'Seattle, WA',
        destination: 'Boston, MA',
        carrier: 'Express Delivery',
        assignedUserEmail: 'john@example.com',
      },
      {
        trackingNumber: 'TRK001234570',
        userId: user.id,
        agencyId: 'agency2',
        status: 'Processing',
        deliveryEstimate: '2025-06-20',
        origin: 'Denver, CO',
        destination: 'Phoenix, AZ',
        carrier: 'FastShip Logistics',
        assignedUserEmail: 'john@example.com',
      },
      {
        trackingNumber: 'TRK001234571',
        userId: user.id,
        agencyId: 'agency2',
        status: 'Out for Delivery',
        deliveryEstimate: '2025-06-17',
        origin: 'Portland, OR',
        destination: 'San Francisco, CA',
        carrier: 'QuickDelivery Corp',
        assignedUserEmail: 'john@example.com',
      },
    ];

    for (const packageData of packages) {
      const packageEntity = this.packageRepository.create(packageData);
      await this.packageRepository.save(packageEntity);
      this.logger.log(`Created package: ${packageData.trackingNumber}`);
    }
  }

  private async seedPackageStatuses(): Promise<void> {
    this.logger.log('Seeding package statuses...');

    // Get all packages
    const packages = await this.packageRepository.find();

    // Create status history for the first package (TRK001234567)
    const package1 = packages.find(p => p.trackingNumber === 'TRK001234567');
    if (package1) {
      const statuses1 = [
        {
          status: 'Created',
          timestamp: new Date('2025-06-10T09:00:00Z'),
          location: 'New York, NY',
          packageId: package1.id,
        },
        {
          status: 'In Transit',
          timestamp: new Date('2025-06-11T14:30:00Z'),
          location: 'Chicago, IL',
          packageId: package1.id,
        },
      ];

      for (const statusData of statuses1) {
        const status = this.packageStatusRepository.create(statusData);
        await this.packageStatusRepository.save(status);
      }
    }

    // Create status history for delivered package (TRK001234568)
    const package2 = packages.find(p => p.trackingNumber === 'TRK001234568');
    if (package2) {
      const statuses2 = [
        {
          status: 'Created',
          timestamp: new Date('2025-06-08T08:00:00Z'),
          location: 'Chicago, IL',
          packageId: package2.id,
        },
        {
          status: 'In Transit',
          timestamp: new Date('2025-06-08T16:00:00Z'),
          location: 'Atlanta, GA',
          packageId: package2.id,
        },
        {
          status: 'Out for Delivery',
          timestamp: new Date('2025-06-10T07:00:00Z'),
          location: 'Miami, FL',
          packageId: package2.id,
        },
        {
          status: 'Delivered',
          timestamp: new Date('2025-06-10T15:30:00Z'),
          location: 'Miami, FL',
          packageId: package2.id,
        },
      ];

      for (const statusData of statuses2) {
        const status = this.packageStatusRepository.create(statusData);
        await this.packageStatusRepository.save(status);
      }
    }

    // Create initial status for other packages
    for (const pkg of packages) {
      if (!['TRK001234567', 'TRK001234568'].includes(pkg.trackingNumber)) {
        const initialStatus = this.packageStatusRepository.create({
          status: pkg.status,
          timestamp: pkg.createdAt,
          location: pkg.origin,
          packageId: pkg.id,
        });
        await this.packageStatusRepository.save(initialStatus);
      }
    }

    this.logger.log('Package statuses seeded successfully');
  }

  async clearDatabase(): Promise<void> {
    this.logger.log('Clearing database...');
    
    // Delete in reverse order due to foreign key constraints
    await this.packageStatusRepository.delete({});
    await this.packageRepository.delete({});
    await this.userRepository.delete({});
    
    this.logger.log('Database cleared successfully');
  }
}