import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { SeedingService } from './database/seeding.service';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

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
  
<<<<<<< HEAD

    // Swagger configuration
  const config = new DocumentBuilder()
    .setTitle('Delivery Tracker API')
    .setDescription('API documentation for Delivery Tracker application')
    .setVersion('1.0')
    .addTag('auth', 'Authentication endpoints')
    .addTag('users', 'User management endpoints')
    .addTag('packages', 'Package tracking endpoints')
    .addBearerAuth() // If you use JWT authentication
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);
  
  await app.listen(3000);
=======
  await app.listen(process.env.PORT || 3000);
>>>>>>> 09b148f452c742a20cde8fd5e7e255b5b1b1f451
  console.log('Application is running on: http://localhost:3000');
}

bootstrap();