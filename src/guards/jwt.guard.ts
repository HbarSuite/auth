import { ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { AuthGuard } from '@nestjs/passport'
import { IS_PUBLIC } from '@hsuite/auth-types'

/**
 * JWT-based Authentication Guard.
 * 
 * @description
 * This guard implements JWT-based authentication protection for routes.
 * It provides:
 * - Route protection requiring valid JWT tokens
 * - Public route exclusions via metadata
 * - Login endpoint bypass
 * - JWT validation through Passport
 * 
 * The guard integrates with NestJS's authentication system and the JWT strategy
 * to protect routes requiring valid JWT authentication.
 * 
 * @class
 * @extends {AuthGuard('jwt')}
 * 
 * @example
 * ```typescript
 * // Protect a route with JWT authentication
 * @UseGuards(JwtAuthGuard)
 * @Get('protected')
 * getProtectedResource() {
 *   // Only accessible with valid JWT token
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
export class JwtAuthGuard extends AuthGuard('jwt') {
  /**
   * Creates an instance of JwtAuthGuard.
   * 
   * @constructor
   * @param {Reflector} reflector - NestJS reflector for accessing route metadata
   */
  constructor(
    private reflector: Reflector
  ) {
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
   * 3. Delegates to JWT strategy for token validation
   * 
   * For protected routes, it uses Passport's JWT strategy to
   * validate the token before granting access.
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

    return <boolean> super.canActivate(context);
  }

  /**
   * Processes authentication results.
   * 
   * @param {Error} err - Authentication error if any
   * @param {any} user - Authenticated user data from JWT payload
   * @param {any} info - Additional authentication info
   * @returns {any} Processed user data
   * @throws {UnauthorizedException} If authentication fails
   * 
   * @description
   * This method:
   * 1. Handles authentication results from the JWT strategy
   * 2. Processes any JWT validation errors
   * 3. Validates user data from token payload
   * 4. Returns authenticated user data for request
   * 
   * It ensures proper error handling and user validation
   * before allowing access to protected routes.
   */
  handleRequest(err, user, info) {
    if (err || !user) {
      throw err || new UnauthorizedException();
    }
    return user;
  }
}