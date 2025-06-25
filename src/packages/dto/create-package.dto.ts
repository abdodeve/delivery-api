import { IsString, IsEmail, IsDateString } from 'class-validator';

export class CreatePackageDto {
  @IsString()
  trackingNumber: string;

  @IsString()
  userId: string;

  @IsString()
  agencyId: string;

  @IsString()
  status: string;

  @IsDateString()
  deliveryEstimate: string;

  @IsString()
  origin: string;

  @IsString()
  destination: string;

  @IsString()
  carrier: string;

  @IsEmail()
  assignedUserEmail: string;
}