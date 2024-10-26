import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user/user.entity';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async register(username: string, password: string): Promise<User> {
    try {
      const existingUser = await this.usersRepository.findOne({
        where: { username },
      });
      if (existingUser) {
        throw new HttpException('Username already exists', HttpStatus.CONFLICT);
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = this.usersRepository.create({
        username,
        password: hashedPassword,
      });
      return await this.usersRepository.save(newUser);
    } catch (error) {
      throw new HttpException(
        'Registration failed',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async validateUser(username: string, password: string): Promise<any> {
    try {
      const user = await this.usersRepository.findOne({ where: { username } });
      if (!user) {
        throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
      }
      const isPasswordMatching = await bcrypt.compare(password, user.password);
      if (!isPasswordMatching) {
        throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
      }
      return { username: user?.username, id: user?.id };
    } catch (error) {
      throw new HttpException(
        'Authentication failed',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async login(user: any) {
    try {
      const payload = { username: user.username, sub: user.id };

      //  access token
      const accessToken = this.jwtService.sign(payload, {
        expiresIn: '60s',
      });

      //  refresh token
      const refreshToken = this.jwtService.sign(payload, {
        expiresIn: '7d',
      });

      return {
        access_token: accessToken,
        refresh_token: refreshToken,
      };
    } catch (error) {
      console.error('Error during login:', error);

      if (error.name === 'JsonWebTokenError') {
        throw new HttpException(
          'Invalid token signature',
          HttpStatus.UNAUTHORIZED,
        );
      } else if (error.name === 'TokenExpiredError') {
        throw new HttpException('Token has expired', HttpStatus.UNAUTHORIZED);
      } else {
        throw new HttpException(
          'Failed to generate authentication tokens',
          HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }
    }
  }
  async refresh(refreshToken: string): Promise<string> {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_SECRET || 'secretKey',
      });

      // If valid, create and return a new access token
      const newAccessToken = this.jwtService.sign(
        { username: payload.username, sub: payload.sub },
        { expiresIn: process.env.JWT_AUTHENTICATION_TOKEN_DURATION || '60s' },
      );

      return { access_token: newAccessToken };
    } catch (e) {
      throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);
    }
  }
}
