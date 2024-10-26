import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @UseGuards(AuthGuard('local'))
  @Post('login')
  async login(@Body() body: { username: string; password: string }) {
    return this.authService.validateUser(body.username, body.password);
  }

  @Get('protected')
  getProtectedData(@Request() req) {
    return `This is protected data for user ${req.user.username}`;
  }
}
