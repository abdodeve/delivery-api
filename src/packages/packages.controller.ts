// packages.controller.ts
import { 
  Controller, 
  Get, 
  Post, 
  Body, 
  Patch, 
  Param, 
  Delete, 
  UseGuards, 
  Request 
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { Role } from '../common/enums/role.enum';
import { PackagesService } from './packages.service';
import { CreatePackageDto } from './dto/create-package.dto';
import { UpdatePackageDto } from './dto/update-package.dto';

@ApiTags('packages')
@Controller('packages')
// @UseGuards(JwtAuthGuard, RolesGuard)
// @ApiBearerAuth() // Uncomment when guards are enabled
export class PackagesController {
  constructor(private readonly packagesService: PackagesService) {}

  @Post()
  @Roles(Role.ADMIN)
  @ApiOperation({ 
    summary: 'Create a new package',
    description: 'Creates a new package in the system. Only accessible by admins.'
  })
  @ApiResponse({ 
    status: 201, 
    description: 'Package created successfully',
    type: CreatePackageDto 
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Bad request - Invalid input data' 
  })
  @ApiUnauthorizedResponse({ 
    description: 'Unauthorized - Invalid or missing token' 
  })
  @ApiForbiddenResponse({ 
    description: 'Forbidden - User does not have admin role' 
  })
  create(@Body() createPackageDto: CreatePackageDto) {
    return this.packagesService.create(createPackageDto);
  }

  @Get()
  @ApiOperation({ 
    summary: 'Get all packages',
    description: 'Retrieves all packages. Results are filtered based on user role and permissions.'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'List of packages retrieved successfully',
    type: [CreatePackageDto]
  })
  @ApiUnauthorizedResponse({ 
    description: 'Unauthorized - Invalid or missing token' 
  })
  findAll(@Request() req) {
    return this.packagesService.findAll(req.user);
  }

  @Get(':id')
  @ApiOperation({ 
    summary: 'Get a package by ID',
    description: 'Retrieves a specific package by its ID. Access is controlled based on user permissions.'
  })
  @ApiParam({ 
    name: 'id', 
    description: 'Package unique identifier',
    example: '123e4567-e89b-12d3-a456-426614174000'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Package retrieved successfully',
    type: CreatePackageDto
  })
  @ApiNotFoundResponse({ 
    description: 'Package not found' 
  })
  @ApiUnauthorizedResponse({ 
    description: 'Unauthorized - Invalid or missing token' 
  })
  @ApiForbiddenResponse({ 
    description: 'Forbidden - User does not have access to this package' 
  })
  findOne(@Param('id') id: string, @Request() req) {
    return this.packagesService.findOne(id, req.user);
  }

  @Get(':id/status')
  @ApiOperation({ 
    summary: 'Get package status',
    description: 'Retrieves the current status of a specific package'
  })
  @ApiParam({ 
    name: 'id', 
    description: 'Package unique identifier',
    example: '123e4567-e89b-12d3-a456-426614174000'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Package status retrieved successfully',
    schema: {
      properties: {
        id: { type: 'string' },
        status: { type: 'string' },
        trackingNumber: { type: 'string' },
        lastUpdated: { type: 'string', format: 'date-time' }
      }
    }
  })
  @ApiNotFoundResponse({ 
    description: 'Package not found' 
  })
  @ApiUnauthorizedResponse({ 
    description: 'Unauthorized - Invalid or missing token' 
  })
  @ApiForbiddenResponse({ 
    description: 'Forbidden - User does not have access to this package' 
  })
  getPackageStatus(@Param('id') id: string, @Request() req) {
    return this.packagesService.getPackageStatus(id, req.user);
  }

  @Patch(':id')
  @Roles(Role.ADMIN)
  @ApiOperation({ 
    summary: 'Update a package',
    description: 'Updates package information. Only accessible by admins.'
  })
  @ApiParam({ 
    name: 'id', 
    description: 'Package unique identifier',
    example: '123e4567-e89b-12d3-a456-426614174000'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Package updated successfully',
    type: CreatePackageDto
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Bad request - Invalid input data' 
  })
  @ApiNotFoundResponse({ 
    description: 'Package not found' 
  })
  @ApiUnauthorizedResponse({ 
    description: 'Unauthorized - Invalid or missing token' 
  })
  @ApiForbiddenResponse({ 
    description: 'Forbidden - User does not have admin role' 
  })
  update(
    @Param('id') id: string, 
    @Body() updatePackageDto: UpdatePackageDto, 
    @Request() req
  ) {
    return this.packagesService.update(id, updatePackageDto, req.user);
  }

  @Delete(':id')
  @Roles(Role.ADMIN)
  @ApiOperation({ 
    summary: 'Delete a package',
    description: 'Permanently deletes a package from the system. Only accessible by admins.'
  })
  @ApiParam({ 
    name: 'id', 
    description: 'Package unique identifier',
    example: '123e4567-e89b-12d3-a456-426614174000'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Package deleted successfully',
    schema: {
      properties: {
        message: { type: 'string', example: 'Package deleted successfully' }
      }
    }
  })
  @ApiNotFoundResponse({ 
    description: 'Package not found' 
  })
  @ApiUnauthorizedResponse({ 
    description: 'Unauthorized - Invalid or missing token' 
  })
  @ApiForbiddenResponse({ 
    description: 'Forbidden - User does not have admin role' 
  })
  remove(@Param('id') id: string, @Request() req) {
    return this.packagesService.remove(id, req.user);
  }
}