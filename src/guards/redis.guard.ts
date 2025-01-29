import { ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { AuthGuard } from '@nestjs/passport'
import { IS_PUBLIC } from '@hsuite/auth-types'

/**
 * Redis-based Authentication Guard.
 * 
 * @description
 * This guard implements session-based authentication using Redis as the session store.
 * It provides:
 * - Route protection based on Redis session state
 * - Public route exclusions via metadata
 * - Login endpoint bypass
 * - Session validation through Passport
 * 
 * The guard integrates with NestJS's authentication system to protect routes
 * requiring valid Redis sessions.
 * 
 * @class
 * @extends {AuthGuard('redis')}
 * 
 * @example
 * ```typescript
 * // Protect a route with Redis session authentication
 * @UseGuards(RedisAuthGuard)
 * @Get('protected')
 * getProtectedResource() {
 *   // Only accessible with valid Redis session
 *   return 'Protected data';
 * }
 * 
 * // Mark a route as public
 * @Public()
 * @Get('public')
 * getPublicResource() {
 *   return 'Public data';
 * }
 * ```
 */
@Injectable()
export class RedisAuthGuard extends AuthGuard('redis') {
  /**
   * Creates an instance of RedisAuthGuard.
   * 
   * @constructor
   * @param {Reflector} reflector - NestJS reflector for accessing route metadata
   */
  constructor(private reflector: Reflector) {
    super();
  }
  
  /**
   * Determines if the current request can access the route.
   * 
   * @async
   * @param {ExecutionContext} context - Execution context containing request details
   * @returns {Promise<boolean>} Whether the route can be accessed
   * 
   * @description
   * This method implements the following access control logic:
   * 1. Checks for @Public() decorator to bypass authentication
   * 2. Allows unrestricted access to login endpoints
   * 3. Verifies Redis session authentication state
   * 
   * The method uses Passport's isAuthenticated() to validate
   * the session state in Redis.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    if(context.getHandler().name == 'login') {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    return request.isAuthenticated();
  }

  /**
   * Processes authentication results.
   * 
   * @param {Error} err - Authentication error if any
   * @param {any} user - Authenticated user data
   * @param {any} info - Additional authentication info
   * @returns {any} Processed user data
   * @throws {UnauthorizedException} If authentication fails
   * 
   * @description
   * This method:
   * 1. Handles authentication results from Passport
   * 2. Processes any authentication errors
   * 3. Validates user data presence
   * 4. Returns authenticated user data for request
   * 
   * It ensures proper error handling and user validation
   * before allowing access to protected routes.
   */
  handleRequest(err, user, info): any {
    if (err || !user) {
      throw err || new UnauthorizedException();
    }
    return user;
  }
}