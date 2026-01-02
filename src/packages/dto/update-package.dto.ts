// update-package.dto.ts
import { PartialType } from '@nestjs/swagger'; // Change this import!
import { CreatePackageDto } from './create-package.dto';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdatePackageDto extends PartialType(CreatePackageDto) {
  // All properties are inherited as optional from CreatePackageDto
  // You can add additional documentation here if needed
  
  @ApiPropertyOptional({
    description: 'Tracking number of the package',
    example: 'TRK123456789',
  })
  trackingNumber?: string;

  @ApiPropertyOptional({
    description: 'Current status of the package',
    example: 'Delivered',
  })
  status?: string;

  @ApiPropertyOptional({
    description: 'Estimated delivery date and time',
    example: '2025-01-05T14:30:00Z',
  })
  deliveryEstimate?: string;
}