import { ExecutionContext, Inject, Injectable, UnauthorizedException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { AuthGuard } from '@nestjs/passport'
import { IS_PUBLIC, IAuth } from '@hsuite/auth-types'

/**
 * Guard for Web3 authentication that extends Passport's AuthGuard.
 * 
 * @description
 * This guard provides Web3 wallet-based authentication by:
 * - Checking if routes are public or protected
 * - Handling session-based and JWT authentication
 * - Managing authentication state
 * - Validating authentication results
 * 
 * @example
 * ```typescript
 * // Apply guard to controller or route
 * @UseGuards(Web3AuthGuard)
 * @Controller('protected')
 * export class ProtectedController {
 *   // Protected routes...
 * }
 * ```
 */
@Injectable()
export class Web3AuthGuard extends AuthGuard('web3') {
  /**
   * Creates an instance of Web3AuthGuard.
   * 
   * @param authWeb3Options - Configuration options for Web3 authentication including
   *                         passport strategy and other auth settings
   * @param reflector - Reflector service for accessing route metadata and decorators
   */
  constructor(
    @Inject('authWeb3Options') private authWeb3Options: IAuth.IConfiguration.IWeb3.IOptions & IAuth.IConfiguration.IOptions,
    private reflector: Reflector
  ) {
    super();
  }

  /**
   * Determines if the current request is allowed to activate.
   * 
   * @description
   * This method:
   * 1. Checks if route is marked as public using @Public() decorator
   * 2. Handles Redis session-based auth by logging in the request
   * 3. Delegates to parent AuthGuard for JWT auth
   * 
   * @param context - The execution context containing request details
   * @returns Promise resolving to boolean indicating if request can proceed
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if route is marked as public
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Allow public routes to proceed
    if (isPublic) {
      return true;
    }

    // Handle Redis session-based authentication
    if(
      this.authWeb3Options.passport == IAuth.IConfiguration.IPassportStrategy.REDIS
    ) {
      const result = (await super.canActivate(context)) as boolean;
      const request = context.switchToHttp().getRequest();
  
      await super.logIn(request);
      return result;
    } 
    // Handle JWT authentication
    else {
      return <boolean>super.canActivate(context);
    }
  }

  /**
   * Handles the result of the authentication process.
   * 
   * @description
   * This method validates the authentication result by:
   * - Checking for errors during authentication
   * - Verifying user was successfully authenticated
   * - Throwing UnauthorizedException for failed auth
   * 
   * @param err - Error from authentication process if any
   * @param user - Authenticated user object if successful
   * @param info - Additional authentication info
   * @returns Authenticated user object
   * @throws UnauthorizedException if authentication fails
   */
  handleRequest(err, user, info) {
    if (err || !user) {
      throw err || new UnauthorizedException();
    }

    return user;
  }
}