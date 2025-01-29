import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common'
import { TwoFactoryAuthService } from '../2fa.service'
import { Reflector } from '@nestjs/core'
import { IS_TWO_FACTOR_AUTH } from '@hsuite/auth-types'

/**
 * Guard for Two-Factor Authentication (2FA) route protection.
 * 
 * @description
 * This guard implements route protection using Two-Factor Authentication (2FA).
 * It integrates with the TwoFactoryAuthService to verify 2FA status and handle
 * code validation for protected routes.
 * 
 * Key Features:
 * - Route-level 2FA protection via @TwoFactorAuth() decorator
 * - Automatic 2FA code validation from request body
 * - Integration with TwoFactoryAuthService for verification
 * - Support for both TOTP and SMS-based 2FA
 * 
 * Usage Flow:
 * 1. Decorate route with @TwoFactorAuth()
 * 2. Apply guard using @UseGuards(TwoFactoryAuthGuard)
 * 3. Send 2FA code in request body as 'code_2fa'
 * 4. Guard validates code and allows/denies access
 *
 * @example
 * ```typescript
 * // Basic route protection
 * @UseGuards(TwoFactoryAuthGuard)
 * @TwoFactorAuth()
 * @Get('protected')
 * getProtectedData() {
 *   return 'This endpoint requires 2FA';
 * }
 * 
 * // Combined with other guards
 * @UseGuards(AuthGuard('jwt'), TwoFactoryAuthGuard)
 * @TwoFactorAuth()
 * @Post('sensitive-operation')
 * async performSensitiveOperation(@Body() data: any) {
 *   // This endpoint requires both JWT and 2FA
 * }
 * ```
 * 
 * @throws {UnauthorizedException} 
 * - When 2FA code is missing from request
 * - When 2FA is not enabled for user
 * - When provided 2FA code is invalid
 */
@Injectable()
export class TwoFactoryAuthGuard implements CanActivate {
  /**
   * Creates an instance of TwoFactoryAuthGuard.
   * 
   * @param twoFactoryAuthService - Service handling 2FA operations
   * @param reflector - NestJS Reflector for accessing route metadata
   */
  constructor(
    private twoFactoryAuthService: TwoFactoryAuthService,
    private reflector: Reflector
  ) {}

  /**
   * Validates 2FA requirements and code for protected routes.
   * 
   * @param context - ExecutionContext containing request details
   * @returns Promise<boolean> - True if access is granted, throws otherwise
   * @throws {UnauthorizedException} When 2FA validation fails
   * 
   * @description
   * Validation Process:
   * 1. Checks if route requires 2FA via @TwoFactorAuth() decorator
   * 2. Verifies presence of 2FA code in request body
   * 3. Confirms 2FA is enabled for requesting user
   * 4. Validates provided 2FA code via service
   * 
   * Request Format:
   * ```json
   * {
   *   "code_2fa": "123456" // Required 6-digit code
   * }
   * ```
   */
  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {
    // Check if route requires 2FA
    const isTwoFactorAuth = this.reflector.getAllAndOverride<boolean>(IS_TWO_FACTOR_AUTH, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Skip 2FA check if not required for route
    if (!isTwoFactorAuth) {
      return true;
    }

    const request = context.switchToHttp().getRequest();

    // Verify 2FA code is provided in request
    if (!request.body?.code_2fa) {
      throw new UnauthorizedException('2FA code is required.');
    }

    try {
      // Check if 2FA is enabled for user
      const isEnabled = await this.twoFactoryAuthService.isEnabled(request.user._id);
      if (!isEnabled) {
        throw new UnauthorizedException('2FA is not enabled.');
      }
      
      // Validate the provided 2FA code
      await this.twoFactoryAuthService.createChallenge(request.user._id, request.body.code_2fa);
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException(error.message);
    }

    return true;
  }
}
