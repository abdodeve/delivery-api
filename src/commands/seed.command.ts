import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module';
import { SeedingService } from '../database/seeding.service';

async function bootstrap() {
  const app = await NestFactory.createApplicationContext(AppModule);
  const seedingService = app.get(SeedingService);

  try {
    console.log('🌱 Starting database seeding...');
    await seedingService.seedAll();
    console.log('✅ Database seeding completed successfully!');
  } catch (error) {
    console.error('❌ Error during seeding:', error);
    process.exit(1);
  } finally {
    await app.close();
  }
}

bootstrap();