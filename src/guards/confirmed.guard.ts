import { CanActivate, ExecutionContext, Inject, Injectable, UnauthorizedException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { IAuth, IS_PUBLIC } from '@hsuite/auth-types'
import { UserDocument, UsersService } from '@hsuite/users'

/**
 * Email Confirmation Guard for Web2 Authentication.
 * 
 * @description
 * This guard ensures that users have confirmed their email addresses
 * before accessing protected routes. It provides:
 * - Email confirmation verification
 * - Public route exclusions
 * - Auth endpoint bypasses
 * - User existence validation
 * 
 * The guard is configurable through authentication options and can be
 * disabled if email confirmation is not required.
 * 
 * @class
 * @implements {CanActivate}
 * 
 * @example
 * ```typescript
 * // Protect a route requiring email confirmation
 * @UseGuards(ConfirmedAuthGuard)
 * @Get('sensitive')
 * getSensitiveData() {
 *   // Only accessible by users with confirmed emails
 *   return 'Sensitive data';
 * }
 * 
 * // Public route not requiring confirmation
 * @Public()
 * @Get('public')
 * getPublicData() {
 *   return 'Public data';
 * }
 * ```
 */
@Injectable()
export class ConfirmedAuthGuard implements CanActivate {
  /**
   * Creates an instance of ConfirmedAuthGuard.
   * 
   * @constructor
   * @param {Reflector} reflector - NestJS reflector for accessing route metadata
   * @param {UsersService} usersService - Service for user operations
   * @param {IAuth.IConfiguration.IWeb2.IOptions} authOptions - Authentication configuration
   */
  constructor(
    private reflector: Reflector,
    private usersService: UsersService,
    @Inject('authOptions') private authOptions: IAuth.IConfiguration.IWeb2.IOptions
  ) {}

  /**
   * Determines if the current request can access the route.
   * 
   * @async
   * @param {ExecutionContext} context - Execution context containing request details
   * @returns {Promise<boolean>} Whether the route can be accessed
   * @throws {UnauthorizedException} If user is unauthorized or email unconfirmed
   * 
   * @description
   * This method implements the following verification flow:
   * 1. Checks if email confirmation is required in config
   * 2. Allows access to public routes and auth endpoints
   * 3. Verifies user existence in database
   * 4. Validates email confirmation status
   * 
   * The method ensures that protected routes are only accessible
   * by users who have completed the email confirmation process.
   */
  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {
    if(this.authOptions.confirmation_required) {
      const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [
        context.getHandler(),
        context.getClass(),
      ]);
  
      if (isPublic) {
        return true;
      }
  
      if(
        ['login', 'logout', 'profile'].includes(context.getHandler().name)
      ) {
        return true;
      }

      const request = context.switchToHttp().getRequest();
      if(!request.user) {
        throw new UnauthorizedException('Unauthorized.');
      }

      let userDocument: UserDocument = await this.usersService.findById(request.user._id);
      if(!userDocument) {
        throw new UnauthorizedException('Unauthorized.');
      }

      if(userDocument && !userDocument.confirmed) {
        throw new UnauthorizedException('Please confirm your email address.');
      }

      return true;
    }
    
    return true;
  }
}
