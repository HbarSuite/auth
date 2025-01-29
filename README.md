# @hsuite/auth

A comprehensive authentication library for NestJS applications supporting both Web2 (username/password) and Web3 (wallet-based) authentication methods.

## Features

- **Flexible Authentication Strategies**
  - Web2 (Traditional) Authentication
    - Username/password authentication
    - Email confirmation support
    - Password reset functionality
    - Two-factor authentication (2FA) support
  - Web3 (Blockchain) Authentication
    - Wallet-based authentication
    - Token gating capabilities
    - Web3 session management

- **Multiple Session Management Options**
  - JWT-based authentication
  - Redis session management
  - Secure cookie handling
  - Session serialization

- **Advanced Security Features**
  - Role-based access control
  - Admin-only mode support
  - Email confirmation enforcement
  - Secure password handling
  - Token expiration management

- **Integration Features**
  - Seamless NestJS integration
  - Passport.js strategy support
  - Redis session store support
  - Mailer service integration
  - Twilio integration for 2FA

## Installation

```bash
npm install @hsuite/auth
```

## Module Configuration

The auth module can be configured asynchronously to support dynamic configuration loading:

```typescript
import { AuthModule } from '@hsuite/auth';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    AuthModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (config: ConfigService) => ({
        commonOptions: {
          jwt: {
            secret: config.get('JWT_SECRET'),
            // Additional JWT options
          },
          passport: 'jwt', // or 'redis' for session-based auth
          operator: {
            // Operator configuration
          }
        },
        // Web2-specific options
        web2Options: {
          confirmation_required: true,
          admin_only: false,
          sendMailOptions: {
            // Mail configuration for confirmation and reset
          },
          mailerOptions: {
            // Mailer service configuration
          },
          twilioOptions: {
            // Twilio configuration for 2FA
          }
        },
        // Web3-specific options
        web3Options: {
          tokenGateOptions: {
            // Token gating configuration
          }
        }
      }),
      inject: [ConfigService]
    })
  ]
})
export class AppModule {}
```

## Usage Examples

### Protected Routes

```typescript
import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtAuthGuard, RedisAuthGuard } from '@hsuite/auth';

@Controller('protected')
export class ProtectedController {
  // JWT-protected route
  @UseGuards(JwtAuthGuard)
  @Get('jwt-protected')
  getJwtProtected() {
    return 'This route is protected by JWT authentication';
  }

  // Redis session-protected route
  @UseGuards(RedisAuthGuard)
  @Get('session-protected')
  getSessionProtected() {
    return 'This route is protected by Redis session authentication';
  }
}
```

### User Profile Retrieval

```typescript
import { Controller, Get, Request } from '@nestjs/common';
import { AuthService } from '@hsuite/auth';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Get('profile')
  async getProfile(@Request() req) {
    return this.authService.profile(req.user);
  }
}
```

## Security Considerations

1. **JWT Configuration**
   - Always use strong secrets for JWT signing
   - Configure appropriate token expiration times
   - Store secrets in environment variables

2. **Session Management**
   - Configure secure cookie options
   - Use Redis for session storage in production
   - Implement proper session cleanup

3. **Web3 Security**
   - Validate wallet signatures
   - Implement proper nonce management
   - Configure token gating requirements

## API Documentation

The library exposes several key endpoints and services:

### AuthService

Core service handling authentication operations:
- User profile management
- Authentication state handling
- Session management

### AuthController

Provides REST endpoints for:
- Profile retrieval
- Authentication state management
- Session handling

### Guards

- `JwtAuthGuard`: Protects routes using JWT authentication
- `RedisAuthGuard`: Protects routes using Redis session authentication
- `ConfirmedAuthGuard`: Ensures user email is confirmed

## Contributing

Please read our contributing guidelines before submitting pull requests.

## License

This project is licensed under the terms specified in the project's LICENSE file.

---

<p align="center">
  Built with ❤️ by the HbarSuite Team<br>
  Copyright © 2024 HbarSuite. All rights reserved.
</p>