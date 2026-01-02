import { 
  Controller, 
  Get, 
  Post, 
  Body, 
  Param, 
  Delete, 
  UseGuards, 
  ClassSerializerInterceptor, 
  UseInterceptors 
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
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';

@ApiTags('users')
@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiBearerAuth()
@UseInterceptors(ClassSerializerInterceptor)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  @Roles(Role.ADMIN)
  @ApiOperation({ 
    summary: 'Create a new user',
    description: 'Creates a new user in the system. Only accessible by admins. Password will be hashed before storage.'
  })
  @ApiResponse({ 
    status: 201, 
    description: 'User created successfully',
    type: CreateUserDto,
    schema: {
      properties: {
        id: { type: 'string' },
        email: { type: 'string' },
        role: { type: 'string', enum: ['admin', 'user', 'agency'] },
        createdAt: { type: 'string', format: 'date-time' }
      }
    }
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Bad request - Invalid input data or email already exists' 
  })
  @ApiUnauthorizedResponse({ 
    description: 'Unauthorized - Invalid or missing token' 
  })
  @ApiForbiddenResponse({ 
    description: 'Forbidden - User does not have admin role' 
  })
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Get()
  @Roles(Role.ADMIN)
  @ApiOperation({ 
    summary: 'Get all users',
    description: 'Retrieves a list of all users in the system. Only accessible by admins. Passwords are excluded from response.'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'List of users retrieved successfully',
    schema: {
      type: 'array',
      items: {
        properties: {
          id: { type: 'string' },
          email: { type: 'string' },
          role: { type: 'string' },
          createdAt: { type: 'string', format: 'date-time' }
        }
      }
    }
  })
  @ApiUnauthorizedResponse({ 
    description: 'Unauthorized - Invalid or missing token' 
  })
  @ApiForbiddenResponse({ 
    description: 'Forbidden - User does not have admin role' 
  })
  findAll() {
    return this.usersService.findAll();
  }

  @Get(':id')
  @Roles(Role.ADMIN)
  @ApiOperation({ 
    summary: 'Get a user by ID',
    description: 'Retrieves a specific user by their ID. Only accessible by admins. Password is excluded from response.'
  })
  @ApiParam({ 
    name: 'id', 
    description: 'User unique identifier',
    example: '123e4567-e89b-12d3-a456-426614174000'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'User retrieved successfully',
    schema: {
      properties: {
        id: { type: 'string' },
        email: { type: 'string' },
        role: { type: 'string' },
        createdAt: { type: 'string', format: 'date-time' }
      }
    }
  })
  @ApiNotFoundResponse({ 
    description: 'User not found' 
  })
  @ApiUnauthorizedResponse({ 
    description: 'Unauthorized - Invalid or missing token' 
  })
  @ApiForbiddenResponse({ 
    description: 'Forbidden - User does not have admin role' 
  })
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @Delete(':id')
  @Roles(Role.ADMIN)
  @ApiOperation({ 
    summary: 'Delete a user',
    description: 'Permanently deletes a user from the system. Only accessible by admins.'
  })
  @ApiParam({ 
    name: 'id', 
    description: 'User unique identifier',
    example: '123e4567-e89b-12d3-a456-426614174000'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'User deleted successfully',
    schema: {
      properties: {
        message: { type: 'string', example: 'User deleted successfully' }
      }
    }
  })
  @ApiNotFoundResponse({ 
    description: 'User not found' 
  })
  @ApiUnauthorizedResponse({ 
    description: 'Unauthorized - Invalid or missing token' 
  })
  @ApiForbiddenResponse({ 
    description: 'Forbidden - User does not have admin role' 
  })
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }
}