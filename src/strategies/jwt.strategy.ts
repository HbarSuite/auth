import { ExtractJwt, Strategy } from 'passport-jwt'
import { PassportStrategy } from '@nestjs/passport'
import { Inject, Injectable } from '@nestjs/common'
import { Request } from 'express'
import { IAuth } from '@hsuite/auth-types'

/**
 * JWT Authentication Strategy implementation.
 * 
 * @description
 * This strategy implements JWT (JSON Web Token) authentication for the application.
 * It extends Passport's JWT strategy to provide:
 * - Token extraction from multiple sources (cookies and Authorization header)
 * - Token validation and verification
 * - Payload processing and cleanup
 * 
 * The strategy supports both browser-based and API authentication methods,
 * making it versatile for different client types.
 * 
 * @class
 * @extends {PassportStrategy(Strategy)}
 * 
 * @example
 * ```typescript
 * // Using the JWT strategy in a controller
 * @UseGuards(AuthGuard('jwt'))
 * @Get('protected')
 * getProtectedResource() {
 *   // This endpoint requires valid JWT token
 *   return 'Protected data';
 * }
 * ```
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  /**
   * Creates an instance of JwtStrategy.
   * 
   * @constructor
   * @param {IAuth.IConfiguration.IAuthentication} authOptions - Authentication configuration
   * 
   * @description
   * Initializes the JWT strategy with the following configuration:
   * - Multiple token extraction methods (cookies and Authorization header)
   * - Token expiration validation
   * - Secret key verification from auth options
   * 
   * The strategy is configured to:
   * 1. Check for tokens in browser cookies
   * 2. Fall back to Authorization header if no cookie is found
   * 3. Verify token signature and expiration
   */
  constructor(
    @Inject('authOptions') private authOptions: IAuth.IConfiguration.IAuthentication
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        JwtStrategy.fromCookiesInBrowser,
        ExtractJwt.fromAuthHeaderAsBearerToken()
      ]),
      ignoreExpiration: false,
      secretOrKey: authOptions.commonOptions.jwt.secret
    });
  }

  /**
   * Validates and processes the JWT token payload.
   * 
   * @async
   * @param {any} payload - The decoded JWT payload
   * @returns {Promise<any>} Cleaned payload without standard JWT claims
   * 
   * @description
   * This method:
   * 1. Receives the decoded JWT payload after token verification
   * 2. Removes standard JWT claims (exp, iat) for clean user data
   * 3. Returns the processed payload for use in the request
   * 
   * The cleaned payload can then be used to identify and authorize the user
   * in subsequent request processing.
   */
  async validate(payload: any) {
    delete(payload.exp);
    delete(payload.iat);
    return payload;
  }

  /**
   * Extracts JWT token from browser cookies.
   * 
   * @static
   * @param {Request} request - Express request object
   * @returns {string | null} JWT token from cookies or null
   * 
   * @description
   * This method:
   * 1. Checks for the presence of cookies in the request
   * 2. Looks for an 'accessToken' cookie specifically
   * 3. Validates that the token is not empty
   * 
   * This enables seamless authentication for browser-based clients
   * while maintaining compatibility with API clients using headers.
   */
  private static fromCookiesInBrowser(request: Request): string | null {
    if(
      request.cookies && 
      'accessToken' in request.cookies && 
      request.cookies.accessToken.length > 0
    ) {
      return request.cookies.accessToken;
    }
    return null;
  }
}