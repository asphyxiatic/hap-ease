import { Controller } from '@nestjs/common';
import { AuthService } from '../services/auth.service.js';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
}
