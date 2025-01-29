import { Strategy } from 'passport-custom'
import { PassportStrategy } from '@nestjs/passport'
import { Injectable, UnauthorizedException } from '@nestjs/common'
import { Request } from 'express'
import { AuthWeb3Service } from '../auth/web3.service'

/**
 * Strategy for handling Web3 wallet-based authentication.
 * 
 * @description
 * This strategy implements Web3 authentication by:
 * - Validating incoming authentication requests
 * - Processing wallet validation through AuthWeb3Service
 * - Managing authentication state and errors
 * - Integrating with Passport.js authentication framework
 * 
 * @example
 * ```typescript
 * // Register strategy in module
 * @Module({
 *   providers: [Web3Strategy]
 * })
 * 
 * // Use in guard
 * @Injectable() 
 * export class Web3AuthGuard extends AuthGuard('web3') {
 *   // Guard implementation
 * }
 * ```
 */
@Injectable()
export class Web3Strategy extends PassportStrategy(Strategy, 'web3') {
  /**
   * Creates an instance of Web3Strategy.
   * 
   * @description
   * Initializes the strategy with required dependencies and configures
   * the base Passport custom strategy.
   * 
   * @param web3Service - Service handling Web3 authentication operations
   */
  constructor(
    private web3Service: AuthWeb3Service
  ) {
    super();
  }

  /**
   * Validates the incoming authentication request.
   * 
   * @description
   * This method:
   * 1. Extracts wallet payload from request body
   * 2. Validates the wallet through AuthWeb3Service
   * 3. Returns validated wallet or throws UnauthorizedException
   * 
   * The validation process verifies:
   * - Wallet signature
   * - Message contents
   * - Token gate requirements if configured
   * 
   * @param request - Express request object containing auth payload
   * @returns Promise resolving to validated wallet details
   * @throws UnauthorizedException if validation fails or wallet is invalid
   */
  async validate(request: Request): Promise<any> {
    try {
      // Extract payload from request body
      let payload: any = <any> request.body;
      
      // Validate wallet through service
      const wallet = await this.web3Service.validateWallet(payload);
      
      // Throw if wallet validation failed
      if (!wallet) {
        throw new UnauthorizedException();
      }

      return wallet;      
    } catch (error) {
      throw new UnauthorizedException();
    }
  }
}