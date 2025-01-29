import { Controller, BadRequestException, Request, Get } from '@nestjs/common'
import { User } from '@hsuite/users-types'
import { ApiBadRequestResponse, ApiNotFoundResponse, ApiOkResponse, ApiOperation, ApiTags } from '@hsuite/nestjs-swagger'
import { CacheTTL } from '@nestjs/cache-manager'
import { AuthService } from './auth.service'
import { Auth } from '@hsuite/auth-types'

/**
 * Controller handling authentication-related HTTP endpoints.
 * 
 * @description
 * This controller provides REST endpoints for authentication operations including:
 * - User profile retrieval
 * - Authentication state management
 * - Session handling
 * 
 * It supports both Web2 (username/password) and Web3 (wallet) authentication methods
 * and implements caching strategies for optimal performance.
 * 
 * @example
 * ```typescript
 * // Register controller in module
 * @Module({
 *   controllers: [AuthController],
 *   providers: [AuthService]
 * })
 * export class AuthModule {}
 * ```
 */
@Controller('auth')
@ApiTags('auth')
export class AuthController {
  /**
   * Creates an instance of AuthController.
   * 
   * @constructor
   * @param {AuthService} authService - Service handling authentication operations
   */
  constructor(
    private readonly authService: AuthService
  ) {}

  /**
   * Retrieves the authenticated user's profile.
   * 
   * @description
   * This endpoint provides the following functionality:
   * - Validates the authenticated user from the request
   * - Retrieves the user's complete profile via AuthService
   * - Implements 1-second cache for performance optimization
   * 
   * The profile data format varies based on authentication type:
   * - UserSafe for standard user accounts
   * - Web3.Entity for wallet-based authentication
   * - Web3.Login.Response for initial authentication
   * 
   * @async
   * @param {Request} request - Express request object containing authenticated user
   * @returns {Promise<User.Safe | Auth.Credentials.Web3.Entity | Auth.Credentials.Web3.Response.Login>}
   * User profile in appropriate format
   * @throws {BadRequestException} If profile retrieval fails
   * 
   * @example
   * ```typescript
   * // Get authenticated user profile
   * GET /auth/profile
   * Authorization: Bearer <token>
   * ```
   */
  @Get('profile')
  @CacheTTL(1)
  @ApiOperation({
    summary: 'Get authenticated user profile from session',
    description: 'Returns the profile of the authenticated user from their active session. Requires valid authentication.'
  })
  @ApiOkResponse({
    type: () => User.Safe,
    status: 200,
    description: "Returns the user's safe profile data"
  })
  @ApiNotFoundResponse({
    description: 'User profile not found'
  })
  @ApiBadRequestResponse({
    description: 'Invalid request or authentication failure'
  })
  async profile(
    @Request() request
  ): Promise<User.Safe | Auth.Credentials.Web3.Entity | Auth.Credentials.Web3.Response.Login> {
    try {
      // Get profile from auth service using authenticated user
      return await this.authService.profile(request.user);
    } catch(error) {
      // Propagate errors as BadRequestException
      throw new BadRequestException(error.message);
    }
  }
}
