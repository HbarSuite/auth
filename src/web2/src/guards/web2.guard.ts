import { ExecutionContext, Inject, Injectable, UnauthorizedException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { AuthGuard } from '@nestjs/passport'
import { IS_PUBLIC, IAuth } from '@hsuite/auth-types'

/**
 * Guard for protecting routes that require Web2 authentication.
 * 
 * @description
 * This guard extends Passport's AuthGuard to provide Web2 authentication by:
 * 1. Checking if routes are marked as public
 * 2. Handling both Redis and JWT authentication strategies
 * 3. Managing user sessions and login state
 * 
 * @example
 * ```typescript
 * @UseGuards(Web2AuthGuard)
 * @Get('protected')
 * protectedRoute() {
 *   return 'Only authenticated users can see this';
 * }
 * ```
 * 
 * @publicApi
 * @extends {AuthGuard}
 */
@Injectable()
export class Web2AuthGuard extends AuthGuard('web2') {
  /**
   * Creates an instance of Web2AuthGuard.
   * 
   * @param authWeb2Options - Configuration options for Web2 authentication
   * @param reflector - Reflector for accessing route metadata
   * 
   * @description
   * Initializes the guard with required dependencies:
   * - authWeb2Options for authentication configuration
   * - reflector for accessing route metadata
   * 
   * @public
   */
  constructor(
    @Inject('authWeb2Options') private authWeb2Options: IAuth.IConfiguration.IWeb2.IOptions & IAuth.IConfiguration.IOptions,
    private reflector: Reflector
  ) {
    super();
  }

  /**
   * Determines if the current request is allowed to activate.
   * 
   * @param context - The execution context of the current request
   * @returns Promise resolving to boolean indicating access permission
   * 
   * @description
   * Validates the request by:
   * 1. Checking if route is marked as public
   * 2. Handling Redis-based authentication if configured
   * 3. Falling back to JWT authentication otherwise
   * 
   * @public
   * @async
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if route is marked as public using @Public() decorator
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Allow access to public routes without authentication
    if (isPublic) {
      return true;
    }

    // Handle Redis-based session authentication
    if(
      this.authWeb2Options.passport == IAuth.IConfiguration.IPassportStrategy.REDIS
    ) {
      const result = (await super.canActivate(context)) as boolean;
      const request = context.switchToHttp().getRequest();
  
      await super.logIn(request);
      return result;
    } 
    // Handle JWT-based authentication
    else {
      return <boolean>super.canActivate(context);
    }
  }

  /**
   * Handles the result of authentication.
   * 
   * @param err - Any error that occurred during authentication
   * @param user - The authenticated user
   * @param info - Additional info from the authentication process
   * @returns The authenticated user object
   * @throws {UnauthorizedException} if authentication fails
   * 
   * @description
   * Processes authentication result by:
   * 1. Checking for authentication errors
   * 2. Verifying user object exists
   * 3. Throwing UnauthorizedException on failure
   * 
   * @public
   */
  handleRequest(err, user, info) {
    // Throw error if authentication failed or no user found
    if (err || !user) {
      throw err || new UnauthorizedException();
    }

    return user;
  }
}