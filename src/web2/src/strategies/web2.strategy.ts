import { PassportStrategy } from "@nestjs/passport"
import { Strategy } from "passport-custom"
import { AuthWeb2Service } from "../auth/web2.service"
import { Inject, Injectable, UnauthorizedException } from "@nestjs/common"
import { Request } from 'express'
import { User } from '@hsuite/users-types'
import { IAuth, Auth } from '@hsuite/auth-types'

/**
 * Strategy for handling Web2 authentication using Passport.
 * 
 * @description
 * This strategy extends PassportStrategy to implement custom authentication logic
 * for traditional username/password (Web2) authentication flows. It validates
 * user credentials and integrates with the AuthWeb2Service.
 * 
 * @example
 * ```typescript
 * // Using the strategy in a module
 * @Module({
 *   providers: [Web2Strategy]
 * })
 * 
 * // Protected route using the strategy
 * @UseGuards(AuthGuard('web2'))
 * @Get('protected')
 * getProtected() {
 *   return 'This route is protected by Web2 auth';
 * }
 * ```
 * 
 * @publicApi
 * @implements {PassportStrategy}
 */
@Injectable()
export class Web2Strategy extends PassportStrategy(Strategy, 'web2') {
    /**
     * Creates an instance of Web2Strategy.
     * 
     * @param authWeb2Options - Configuration options for Web2 authentication
     * @param web2Service - Service handling Web2 authentication logic
     * 
     * @description
     * Initializes the strategy with required dependencies:
     * - authWeb2Options for authentication configuration
     * - web2Service for handling user validation
     * 
     * @public
     */
    constructor(
        @Inject('authWeb2Options') private authWeb2Options: IAuth.IConfiguration.IWeb2.IOptions,
        private web2Service: AuthWeb2Service
    ) {
        super();
    }

    /**
     * Validates user credentials from the request.
     * 
     * @param request - The Express request object containing credentials
     * @returns Promise resolving to validated user or null
     * @throws {UnauthorizedException} If credentials are invalid
     * 
     * @description
     * Performs user validation by:
     * 1. Extracting credentials from request body
     * 2. Validating credentials using AuthWeb2Service
     * 3. Throwing UnauthorizedException for invalid credentials
     * 
     * The validated user object is added to the request for use in
     * subsequent request processing.
     * 
     * @example
     * ```typescript
     * // Strategy automatically validates requests
     * @UseGuards(AuthGuard('web2'))
     * @Get('profile')
     * getProfile(@Request() req) {
     *   return req.user; // Validated user object
     * }
     * ```
     * 
     * @public
     * @async
     */
    async validate(request: Request): Promise<User.Safe | null> {
        // Extract signup credentials from request body
        let payload: Auth.Credentials.Web2.Dto.Signup = <any> request.body;
        
        // Attempt to validate user credentials
        const user = await this.web2Service.validateUser(payload);

        // Throw unauthorized exception if user validation fails
        if(!user) {
            throw new UnauthorizedException();
        }

        return user;
    }
}