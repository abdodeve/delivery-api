// auth.controller.ts
import { Controller, Request, Post, UseGuards, Body } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiUnauthorizedResponse,
  ApiBearerAuth,
  ApiProperty
} from '@nestjs/swagger';
import { LocalAuthGuard } from '../auth/guards/local-auth.guard';
import { AuthService } from './auth.service';

class LoginDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'SecurePass123',
  })
  password: string;
}

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @ApiOperation({ 
    summary: 'User login',
    description: 'Authenticates a user with email and password, returns JWT access token'
  })
  @ApiBody({
    type: LoginDto,
    description: 'User credentials',
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Login successful',
    schema: {
      properties: {
        access_token: { 
          type: 'string', 
          example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          description: 'JWT token for authentication'
        },
        user: {
          type: 'object',
          properties: {
            id: { type: 'string', example: '123e4567-e89b-12d3-a456-426614174000' },
            email: { type: 'string', example: 'user@example.com' },
            role: { type: 'string', example: 'user', enum: ['admin', 'user', 'agency'] }
          }
        }
      }
    }
  })
  @ApiUnauthorizedResponse({ 
    description: 'Invalid credentials',
    schema: {
      properties: {
        statusCode: { type: 'number', example: 401 },
        message: { type: 'string', example: 'Unauthorized' }
      }
    }
  })
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  @Post('logout')
  @ApiBearerAuth()
  @ApiOperation({ 
    summary: 'User logout',
    description: 'Logs out the current user. In production, this should invalidate/blacklist the JWT token.'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Logout successful',
    schema: {
      properties: {
        message: { 
          type: 'string', 
          example: 'Logged out successfully' 
        }
      }
    }
  })
  @ApiResponse({ 
    status: 401, 
    description: 'Unauthorized - Invalid or missing token' 
  })
  async logout() {
    // In a real app, you might want to blacklist the token
    return { message: 'Logged out successfully' };
  }
}