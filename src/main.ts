import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { UserService } from './user/user.service';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());

  app.enableCors({
    origin: 'http://localhost:3000', // Replace with your frontend origin
    credentials: true, // Allow cookies to be sent
  });

  const userService = app.get(UserService);

  await userService.createDummyUser();
  await app.listen(3001);
}
bootstrap();
