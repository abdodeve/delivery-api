import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { SeedingService } from './database/seeding.service';
import { ExpressAdapter } from '@nestjs/platform-express';
import * as express from 'express';

// Create Express server for Vercel
const server = express();
let app: any;

async function createNestApp() {
  if (!app) {
    app = await NestFactory.create(AppModule, new ExpressAdapter(server));
    
    // Enable CORS
    app.enableCors();
    
    // Global validation pipe
    app.useGlobalPipes(new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }));

    // Auto-seed in development (be careful with this on Vercel)
    if (process.env.NODE_ENV !== 'production') {
      const seedingService = app.get(SeedingService);
      await seedingService.seedAll();
    }
    
    await app.init();
  }
  return app;
}

// For local development
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  app.enableCors();
  
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    transform: true,
    forbidNonWhitelisted: true,
  }));

  if (process.env.NODE_ENV !== 'production') {
    const seedingService = app.get(SeedingService);
    await seedingService.seedAll();
  }
  
  await app.listen(3000);
  console.log('Application is running on: http://localhost:3000');
}

// Export for Vercel
export default async (req: any, res: any) => {
  await createNestApp();
  return server(req, res);
};

// Run locally if not in serverless environment
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  bootstrap();
}