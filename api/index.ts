import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from '../src/app.module';

let app: any;

async function createApp() {
  if (!app) {
    app = await NestFactory.create(AppModule);
    
    app.enableCors();
    
    app.useGlobalPipes(new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }));
    
    // Skip seeding on Vercel to avoid issues
    await app.init();
  }
  return app;
}

export default async (req: any, res: any) => {
  try {
    const app = await createApp();
    const httpAdapter = app.getHttpAdapter();
    return httpAdapter.getInstance()(req, res);
  } catch (error) {
    console.error('Error in serverless function:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
};