#!/bin/bash

# NestJS Project Structure Setup Script
# This script creates the directory structure and files for a NestJS project

echo "Creating NestJS project structure..."

# Create main directories
mkdir -p src/auth/guards
mkdir -p src/users/entities
mkdir -p src/users/dto
mkdir -p src/packages/entities
mkdir -p src/packages/dto
mkdir -p src/common/decorators
mkdir -p src/common/enums

echo "✅ Directories created successfully!"

# Create main app files
cat > src/main.ts << 'EOF'
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }));
  
  await app.listen(3000);
  console.log('Application is running on: http://localhost:3000');
}
bootstrap();
EOF

cat > src/app.module.ts << 'EOF'
import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { PackagesModule } from './packages/packages.module';

@Module({
  imports: [AuthModule, UsersModule, PackagesModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
EOF

# Create Auth module files
cat > src/auth/auth.module.ts << 'EOF'
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { LocalStrategy } from './local.strategy';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'your-secret-key',
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
EOF

cat > src/auth/auth.service.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(username: string, password: string): Promise<any> {
    const user = await this.usersService.findByUsername(username);
    if (user && await bcrypt.compare(password, user.password)) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    const payload = { username: user.username, sub: user.id, role: user.role };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
EOF

cat > src/auth/auth.controller.ts << 'EOF'
import { Controller, Request, Post, UseGuards, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }
}
EOF

cat > src/auth/local.strategy.ts << 'EOF'
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super();
  }

  async validate(username: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(username, password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
EOF

cat > src/auth/jwt.strategy.ts << 'EOF'
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'your-secret-key',
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, username: payload.username, role: payload.role };
  }
}
EOF

cat > src/auth/guards/roles.guard.ts << 'EOF'
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '../../common/enums/role.enum';
import { ROLES_KEY } from '../../common/decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles) {
      return true;
    }
    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some((role) => user.role?.includes(role));
  }
}
EOF

# Create Users module files
cat > src/users/users.module.ts << 'EOF'
import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';

@Module({
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
EOF

cat > src/users/users.service.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  private users: User[] = [];

  async create(createUserDto: CreateUserDto): Promise<User> {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const user = {
      id: Date.now(),
      username: createUserDto.username,
      email: createUserDto.email,
      password: hashedPassword,
      role: createUserDto.role,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.users.push(user);
    return user;
  }

  async findAll(): Promise<User[]> {
    return this.users.map(({ password, ...user }) => user as User);
  }

  async findOne(id: number): Promise<User> {
    const user = this.users.find(user => user.id === id);
    if (user) {
      const { password, ...result } = user;
      return result as User;
    }
    return null;
  }

  async findByUsername(username: string): Promise<User> {
    return this.users.find(user => user.username === username);
  }
}
EOF

cat > src/users/users.controller.ts << 'EOF'
import { Controller, Get, Post, Body, Param, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { Role } from '../common/enums/role.enum';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.Admin)
  findAll() {
    return this.usersService.findAll();
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(+id);
  }
}
EOF

cat > src/users/entities/user.entity.ts << 'EOF'
import { Role } from '../../common/enums/role.enum';

export class User {
  id: number;
  username: string;
  email: string;
  password?: string;
  role: Role;
  createdAt: Date;
  updatedAt: Date;
}
EOF

cat > src/users/dto/create-user.dto.ts << 'EOF'
import { IsEmail, IsNotEmpty, IsString, IsEnum } from 'class-validator';
import { Role } from '../../common/enums/role.enum';

export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  username: string;

  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;

  @IsEnum(Role)
  role: Role;
}
EOF

# Create Packages module files
cat > src/packages/packages.module.ts << 'EOF'
import { Module } from '@nestjs/common';
import { PackagesService } from './packages.service';
import { PackagesController } from './packages.controller';

@Module({
  controllers: [PackagesController],
  providers: [PackagesService],
})
export class PackagesModule {}
EOF

cat > src/packages/packages.service.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { CreatePackageDto } from './dto/create-package.dto';
import { UpdatePackageDto } from './dto/update-package.dto';
import { Package } from './entities/package.entity';
import { PackageStatus } from './entities/package-status.entity';

@Injectable()
export class PackagesService {
  private packages: Package[] = [];

  create(createPackageDto: CreatePackageDto): Package {
    const package = {
      id: Date.now(),
      ...createPackageDto,
      status: PackageStatus.PENDING,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.packages.push(package);
    return package;
  }

  findAll(): Package[] {
    return this.packages;
  }

  findOne(id: number): Package {
    return this.packages.find(pkg => pkg.id === id);
  }

  update(id: number, updatePackageDto: UpdatePackageDto): Package {
    const packageIndex = this.packages.findIndex(pkg => pkg.id === id);
    if (packageIndex !== -1) {
      this.packages[packageIndex] = {
        ...this.packages[packageIndex],
        ...updatePackageDto,
        updatedAt: new Date(),
      };
      return this.packages[packageIndex];
    }
    return null;
  }

  remove(id: number): boolean {
    const packageIndex = this.packages.findIndex(pkg => pkg.id === id);
    if (packageIndex !== -1) {
      this.packages.splice(packageIndex, 1);
      return true;
    }
    return false;
  }
}
EOF

cat > src/packages/packages.controller.ts << 'EOF'
import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards } from '@nestjs/common';
import { PackagesService } from './packages.service';
import { CreatePackageDto } from './dto/create-package.dto';
import { UpdatePackageDto } from './dto/update-package.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('packages')
@UseGuards(JwtAuthGuard)
export class PackagesController {
  constructor(private readonly packagesService: PackagesService) {}

  @Post()
  create(@Body() createPackageDto: CreatePackageDto) {
    return this.packagesService.create(createPackageDto);
  }

  @Get()
  findAll() {
    return this.packagesService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.packagesService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updatePackageDto: UpdatePackageDto) {
    return this.packagesService.update(+id, updatePackageDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.packagesService.remove(+id);
  }
}
EOF

cat > src/packages/entities/package.entity.ts << 'EOF'
import { PackageStatus } from './package-status.entity';

export class Package {
  id: number;
  name: string;
  description: string;
  weight: number;
  dimensions: string;
  senderAddress: string;
  recipientAddress: string;
  status: PackageStatus;
  trackingNumber: string;
  createdAt: Date;
  updatedAt: Date;
}
EOF

cat > src/packages/entities/package-status.entity.ts << 'EOF'
export enum PackageStatus {
  PENDING = 'pending',
  IN_TRANSIT = 'in_transit',
  DELIVERED = 'delivered',
  RETURNED = 'returned',
  CANCELLED = 'cancelled',
}
EOF

cat > src/packages/dto/create-package.dto.ts << 'EOF'
import { IsNotEmpty, IsString, IsNumber, IsOptional } from 'class-validator';

export class CreatePackageDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsNumber()
  weight: number;

  @IsString()
  dimensions: string;

  @IsNotEmpty()
  @IsString()
  senderAddress: string;

  @IsNotEmpty()
  @IsString()
  recipientAddress: string;

  @IsOptional()
  @IsString()
  trackingNumber?: string;
}
EOF

cat > src/packages/dto/update-package.dto.ts << 'EOF'
import { PartialType } from '@nestjs/mapped-types';
import { CreatePackageDto } from './create-package.dto';
import { IsOptional, IsEnum } from 'class-validator';
import { PackageStatus } from '../entities/package-status.entity';

export class UpdatePackageDto extends PartialType(CreatePackageDto) {
  @IsOptional()
  @IsEnum(PackageStatus)
  status?: PackageStatus;
}
EOF

# Create Common files
cat > src/common/enums/role.enum.ts << 'EOF'
export enum Role {
  User = 'user',
  Admin = 'admin',
  Moderator = 'moderator',
}
EOF

cat > src/common/decorators/roles.decorator.ts << 'EOF'
import { SetMetadata } from '@nestjs/common';
import { Role } from '../enums/role.enum';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
EOF

# Create additional guard files
cat > src/auth/guards/local-auth.guard.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
EOF

cat > src/auth/guards/jwt-auth.guard.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
EOF

echo "✅ All files created successfully!"
echo ""
echo "📦 Next steps:"
echo "1. Install required dependencies:"
echo "   npm install @nestjs/passport @nestjs/jwt passport passport-local passport-jwt bcrypt class-validator class-transformer"
echo "   npm install -D @types/passport-local @types/passport-jwt @types/bcrypt"
echo ""
echo "2. Run the application:"
echo "   npm run start:dev"
echo ""
echo "🚀 Your NestJS project structure is ready!"