import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from '../src/app.module';

let app: any;

async function createApp() {
  if (!app) {
    console.log('Creating NestJS app...');
    app = await NestFactory.create(AppModule);
    
    app.enableCors();
    
    app.useGlobalPipes(new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }));
    
    await app.init();
    console.log('NestJS app created successfully');
  }
  return app;
}

export default async (req: any, res: any) => {
  try {
    console.log('Serverless function called:', req.method, req.url);
    const app = await createApp();
    const httpAdapter = app.getHttpAdapter();
    const handler = httpAdapter.getInstance();
    return handler(req, res);
  } catch (error) {
    console.error('Serverless function error:', error);
    return res.status(500).json({ 
      error: 'Internal Server Error', 
      details: error.message,
      stack: error.stack 
    });
  }
};