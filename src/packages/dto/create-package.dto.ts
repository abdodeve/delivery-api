// create-package.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsEmail, IsDateString } from 'class-validator';

export class CreatePackageDto {
  @ApiProperty({
    description: 'Tracking number of the package',
    example: 'TRK123456789',
  })
  @IsString()
  trackingNumber: string;

  @ApiProperty({
    description: 'ID of the user who owns the package',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @IsString()
  userId: string;

  @ApiProperty({
    description: 'ID of the agency handling the package',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @IsString()
  agencyId: string;

  @ApiProperty({
    description: 'Current status of the package',
    example: 'In Transit',
    enum: ['Pending', 'In Transit', 'Out for Delivery', 'Delivered', 'Failed'],
  })
  @IsString()
  status: string;

  @ApiProperty({
    description: 'Estimated delivery date and time',
    example: '2025-01-05T14:30:00Z',
    format: 'date-time',
  })
  @IsDateString()
  deliveryEstimate: string;

  @ApiProperty({
    description: 'Origin location of the package',
    example: 'Paris, France',
  })
  @IsString()
  origin: string;

  @ApiProperty({
    description: 'Destination location of the package',
    example: 'Lyon, France',
  })
  @IsString()
  destination: string;

  @ApiProperty({
    description: 'Carrier/shipping company name',
    example: 'DHL',
    enum: ['DHL', 'FedEx', 'UPS', 'Colissimo', 'Chronopost'],
  })
  @IsString()
  carrier: string;

  @ApiProperty({
    description: 'Email of the user assigned to handle this package',
    example: 'handler@example.com',
    format: 'email',
  })
  @IsEmail()
  assignedUserEmail: string;
}