import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async findOne(username: string): Promise<User | undefined> {
    return this.userRepository.findOne({ where: { username } });
  }

  async validatePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  async createUser(username: string, password: string): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = this.userRepository.create({
      username,
      password: hashedPassword,
    });
    return this.userRepository.save(newUser);
  }

  async createDummyUser() {
    const username = 'testuser';
    const password = 'testpassword'; // Use a strong password in production

    const existingUser = await this.findOne(username);
    if (existingUser) {
      console.log('User already exists.');
      return existingUser;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = this.userRepository.create({
      username,
      password: hashedPassword,
    });
    await this.userRepository.save(newUser);
    console.log('Dummy user created:', newUser);
    return newUser;
  }
}
