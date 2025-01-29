import { BadRequestException, Controller, Get, Post, Query, Request } from '@nestjs/common'
import { TwoFactoryAuthService } from './2fa.service'
import { 
  ApiBadRequestResponse, 
  ApiExcludeEndpoint, 
  ApiNotFoundResponse, 
  ApiOkResponse, 
  ApiOperation, 
  ApiTags 
} from '@hsuite/nestjs-swagger'
import { Auth, IAuth } from '@hsuite/auth-types'

/**
 * Controller for handling Two-Factor Authentication (2FA) operations.
 * 
 * @description
 * This controller provides endpoints for managing 2FA functionality including:
 * - Creating new 2FA factors
 * - Verifying 2FA factors
 * - Deleting 2FA factors
 * - Creating and verifying 2FA challenges
 * 
 * All endpoints require user authentication and handle 2FA operations for the authenticated user.
 * 
 * @example
 * ```typescript
 * // Creating a new 2FA factor
 * POST /auth/2fa/factor/create
 * 
 * // Verifying a 2FA factor
 * POST /auth/2fa/factor/verify?code=123456
 * 
 * // Deleting a 2FA factor
 * POST /auth/2fa/factor/delete?code=123456
 * 
 * // Verifying a 2FA challenge
 * GET /auth/2fa/challenge/verify?code=123456
 * ```
 * 
 * @class
 * @public
 */
@Controller('auth/2fa')
@ApiTags('auth/2fa')
export class TwoFactoryAuthController {
  /**
   * Creates an instance of TwoFactoryAuthController.
   * 
   * @param {TwoFactoryAuthService} twoFactoryAuthService - Service handling 2FA business logic
   * @description 
   * Initializes controller with required 2FA service dependency.
   * The service handles all business logic for 2FA operations.
   * 
   * @example
   * ```typescript
   * const controller = new TwoFactoryAuthController(twoFactoryAuthService);
   * ```
   */
  constructor(
    private readonly twoFactoryAuthService: TwoFactoryAuthService
  ) {}

  /**
   * Creates a new 2FA factor for the authenticated user.
   * 
   * @param {Request} request - Express request object containing authenticated user info
   * @returns {Promise<IAuth.ITwoFactor.IResponse.ICreate>} Response containing the created factor details
   * @throws {BadRequestException} If factor creation fails due to invalid user or existing factor
   * 
   * @description
   * Initiates the creation of a new 2FA factor for the authenticated user.
   * The factor must be verified before it becomes active.
   * Only one active factor is allowed per user.
   * 
   * @example
   * ```typescript
   * // Request
   * POST /auth/2fa/factor/create
   * 
   * // Response
   * {
   *   "factorId": "f123",
   *   "status": "pending",
   *   "createdAt": "2023-01-01T00:00:00Z"
   * }
   * ```
   */
  @ApiOperation({
    summary: 'create a new factor for the logged in user.',
    description: 'This endpoint is only available if the user is authenticated. \
    It will return a new factor for the user.'
  })
  @ApiOkResponse({
    type: () => Auth.TwoFactor.Response.Create,
    status: 200,
    description: "Returns a Auth.Twilio.TwoFactorCreateResponse."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  @Post('factor/create')
  async verifyFactor(
    @Request() request
  ): Promise<IAuth.ITwoFactor.IResponse.ICreate> {
    try {
      return await this.twoFactoryAuthService.createFactor(request.user._id);
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }

  /**
   * Deletes the 2FA factor for the authenticated user.
   * 
   * @param {string} code - Verification code to authorize factor deletion
   * @param {Request} request - Express request object containing authenticated user info
   * @returns {Promise<IAuth.ITwoFactor.IResponse.IDelete>} Response confirming factor deletion
   * @throws {BadRequestException} If factor deletion fails or code is invalid
   * 
   * @description
   * Removes the existing 2FA factor for the user after verifying the provided code.
   * This disables 2FA for the user's account.
   * Requires a valid verification code to confirm the deletion.
   * 
   * @example
   * ```typescript
   * // Request
   * POST /auth/2fa/factor/delete?code=123456
   * 
   * // Response
   * {
   *   "success": true,
   *   "message": "2FA factor deleted successfully",
   *   "deletedAt": "2023-01-01T00:00:00Z"
   * }
   * ```
   */
  @ApiOperation({
    summary: 'delete the factor for the logged in user.',
    description: 'This endpoint is only available if the user is authenticated. \
    It will allow the logged in user to delete the factor.'
  })
  @ApiOkResponse({
    type: () => Auth.TwoFactor.Response.Delete,
    status: 200,
    description: "Returns a Auth.Twilio.TwoFactorDeleteResponse."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  @Post('factor/delete')
  async deleteFactor(
    @Query('code') code: string,
    @Request() request
  ): Promise<IAuth.ITwoFactor.IResponse.IDelete> {
    try {
      return await this.twoFactoryAuthService.deleteFactor(code, request.user._id);
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }

  /**
   * Verifies a newly created 2FA factor.
   * 
   * @param {string} code - Verification code to validate the factor
   * @param {Request} request - Express request object containing authenticated user info
   * @returns {Promise<IAuth.ITwoFactor.IResponse.IVerify>} Response confirming factor verification
   * @throws {BadRequestException} If verification fails or code is invalid
   * 
   * @description
   * Validates and activates a newly created 2FA factor using the provided verification code.
   * Must be called after creating a new factor before 2FA becomes active.
   * The verification code is typically sent via SMS or generated by an authenticator app.
   * 
   * @example
   * ```typescript
   * // Request
   * POST /auth/2fa/factor/verify?code=123456
   * 
   * // Response
   * {
   *   "success": true,
   *   "factorId": "f123",
   *   "status": "active",
   *   "verifiedAt": "2023-01-01T00:00:00Z"
   * }
   * ```
   */
  @ApiOperation({
    summary: 'verify a new factor for the logged in user.',
    description: 'This endpoint is only available if the user is authenticated. \
    It will allow the logged in user to verify a new factor.'
  })
  @ApiOkResponse({
    type: () => Auth.TwoFactor.Response.Verify,
    status: 200,
    description: "Returns a Auth.Twilio.TwoFactorVerifyResponse."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  @Post('factor/verify')
  async createFactor(
    @Query('code') code: string,
    @Request() request
  ): Promise<IAuth.ITwoFactor.IResponse.IVerify> {
    try {
      return await this.twoFactoryAuthService.verifyFactor(
        request.user._id,
        code);
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }

  /**
   * Creates and verifies a 2FA challenge.
   * 
   * @param {string} code - Challenge verification code
   * @param {Request} request - Express request object containing authenticated user info
   * @returns {Promise<IAuth.ITwoFactor.IResponse.IVerify>} Response confirming challenge verification
   * @throws {BadRequestException} If challenge creation/verification fails
   * 
   * @description
   * Creates and immediately verifies a 2FA challenge using the provided code.
   * Used internally by the authentication system to validate 2FA codes during login.
   * This endpoint is excluded from API documentation as it's for internal use.
   * 
   * Challenge verification process:
   * 1. Validates the provided code format
   * 2. Checks if code matches the expected value
   * 3. Verifies code hasn't expired
   * 4. Confirms code hasn't been used before
   * 
   * @example
   * ```typescript
   * // Request
   * GET /auth/2fa/challenge/verify?code=123456
   * 
   * // Response
   * {
   *   "success": true,
   *   "challengeId": "c123",
   *   "verifiedAt": "2023-01-01T00:00:00Z"
   * }
   * ```
   */
  @ApiExcludeEndpoint()
  @ApiOperation({
    summary: 'verify a new factor for the logged in user.',
    description: 'This endpoint is only available if the user is authenticated. \
    It will allow the logged in user to verify a new factor.'
  })
  @ApiOkResponse({
    type: () => Auth.TwoFactor.Response.Verify,
    status: 200,
    description: "Returns a Auth.Twilio.TwoFactorVerifyResponse."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  @Get('challenge/verify')
  async createChallenge(
    @Query('code') code: string,
    @Request() request
  ): Promise<IAuth.ITwoFactor.IResponse.IVerify> {
    try {
      return await this.twoFactoryAuthService.createChallenge(
        request.user._id,
        code);
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }
}
