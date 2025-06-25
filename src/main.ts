import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { SeedingService } from './database/seeding.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Enable CORS
  app.enableCors();
  
  // Global validation pipe
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    transform: true,
    forbidNonWhitelisted: true,
  }));

  // Auto-seed in development
  if (process.env.NODE_ENV !== 'production') {
    const seedingService = app.get(SeedingService);
    await seedingService.seedAll();
  }
  
  await app.listen(process.env.PORT || 3000);
  console.log('Application is running on: http://localhost:3000');
}

bootstrap();