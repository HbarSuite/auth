import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common'

/**
 * Guard to protect routes that should only be accessible by admin users.
 * 
 * @description
 * This guard implements route protection by:
 * 1. Verifying that a user is authenticated
 * 2. Checking if the authenticated user has admin role
 * 3. Throwing UnauthorizedException if conditions aren't met
 * 
 * @example
 * ```typescript
 * @UseGuards(AdminAuthGuard)
 * @Get('admin-only')
 * adminRoute() {
 *   return 'Only admins can see this';
 * }
 * ```
 * 
 * @publicApi
 * @implements {CanActivate}
 */
@Injectable()
export class AdminAuthGuard implements CanActivate {

  /**
   * Creates an instance of AdminAuthGuard.
   * 
   * @description
   * Initializes a new AdminAuthGuard instance.
   * No dependencies are required.
   */
  constructor() {}

  /**
   * Determines if the current user has permission to access the route.
   * 
   * @param context - The execution context containing the request
   * @returns Promise resolving to boolean indicating access permission
   * @throws {UnauthorizedException} if user is not authenticated
   * @throws {UnauthorizedException} if authenticated user is not an admin
   * 
   * @description
   * Validates the request by:
   * 1. Extracting user from request
   * 2. Checking if user exists
   * 3. Verifying user has admin role
   * 
   * @public
   * @async
   */
  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {
    // Get request object from context
    const request = context.switchToHttp().getRequest();

    // Check if user exists in request
    if(!request.user) {
      throw new UnauthorizedException('Unauthorized.');
    }

    // Verify user has admin role
    if(request.user.role != 'admin') {
      throw new UnauthorizedException('Unauthorized, reserved to admins only.');
    }

    return true;
  }
}
