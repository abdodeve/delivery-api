import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { PackagesModule } from './packages/packages.module';
import { User } from './users/entities/user.entity';
import { PackageEntity } from './packages/entities/package.entity';
import { PackageStatus } from './packages/entities/package-status.entity';
import { DatabaseModule } from './database/database.module';


@Module({
  imports: [
    DatabaseModule,
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      url: process.env.DATABASE_URL || 'postgresql://postgres.pggstbperagfkdaviige:H@bchi@1994+@aws-0-eu-west-3.pooler.supabase.com:6543/postgres?pgbouncer=true',
      entities: [User, PackageEntity, PackageStatus],
      synchronize: true, // Set to false in production
      ssl: {
        rejectUnauthorized: false,
      },
    }),
    AuthModule,
    UsersModule,
    PackagesModule,
  ],
})
export class AppModule {}