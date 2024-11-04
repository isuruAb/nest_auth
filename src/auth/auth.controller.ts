// src/auth/auth.controller.ts
import {
  Controller,
  Post,
  Body,
  Request,
  UseGuards,
  Res,
  HttpStatus,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './local-auth.guard';
import { JwtAuthGuard } from './jwt-auth.guard';
import { JwtService } from '@nestjs/jwt';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
  ) {}

  @Post('refresh')
  async refresh(@Request() req, @Res() res) {
    // Get the refresh token from HttpOnly cookie
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token provided');
    }

    try {
      // Validate and generate a new access token
      const newAccessToken =
        await this.authService.refreshAccessToken(refreshToken);

      // Send the new access token in the response body
      return res.status(HttpStatus.OK).json({ access_token: newAccessToken });
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  @Post('register')
  async register(@Body() body: { username: string; password: string }) {
    return this.authService.register(body.username, body.password);
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req, @Res() res) {
    const { access_token, refresh_token } = await this.authService.login(
      req.user,
    );
    // Set the refresh token in a HttpOnly cookie
    res.cookie('refresh_token', refresh_token, {
      httpOnly: true, // Prevents JavaScript access
      secure: true, // Ensures it’s only sent over HTTPS
      sameSite: 'strict', // Protects against CSRF
      maxAge: 7 * 24 * 60 * 60 * 1000, // Cookie expiry (1 week in this example)
    });

    return res.status(HttpStatus.OK).json({ access_token });
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  logout(@Request() req, @Res() res) {
    res.cookie('refresh_token', '', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 0,
    });
    return res.status(HttpStatus.OK).json(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Post('protected')
  getProtected(@Request() req) {
    return req.user;
  }
}
