import { Body, Controller, Post, Request, BadRequestException, Inject, Query } from '@nestjs/common'
import { AuthWeb2Service } from './web2.service'
import { User } from '@hsuite/users-types'
import { ApiBadRequestResponse, ApiBody, ApiNotFoundResponse, ApiOkResponse, ApiOperation, ApiQuery, ApiTags } from '@hsuite/nestjs-swagger'
import { IAuth, Auth, Public } from '@hsuite/auth-types'

/**
 * Controller for handling Web2 authentication operations.
 * 
 * @description
 * This controller provides endpoints for Web2 authentication flows including:
 * - User registration with email/password
 * - Password reset functionality
 * - Email confirmation
 * 
 * All endpoints are public and do not require authentication unless specified.
 * The controller integrates with AuthWeb2Service for business logic.
 */
@Controller('auth/web2')
@ApiTags('auth/web2')
@Public()
export class AuthWeb2AccountsController {
  /**
   * Creates an instance of AuthWeb2AccountsController.
   * 
   * @param authWeb2Options - Configuration options for Web2 authentication
   * @param web2Service - Service handling Web2 authentication logic
   * 
   * @description
   * Initializes the controller with required dependencies for Web2 auth operations
   */
  constructor(
    @Inject('authWeb2Options') private authWeb2Options: IAuth.IConfiguration.IWeb2.IOptions,
    private readonly web2Service: AuthWeb2Service
  ) {}

  /**
   * Registers a new user with email and password.
   * 
   * @param request - The HTTP request object
   * @param credentials - User signup credentials containing email and password
   * @returns Promise resolving to safe user information
   * @throws BadRequestException if user is logged in or registration fails
   * 
   * @description
   * Creates a new user account with the provided credentials.
   * Validates that no user is currently logged in before proceeding.
   */
  @Post('register')
  @ApiOperation({
    summary: 'register a new user with email and password.',
    description: 'This endpoint is always open and does not require authentication. \
    It is used to create a new user in the database. \
    The user will be able to login with the credentials provided.'
  })
  @ApiBody({
    type: () => Auth.Credentials.Web2.Dto.Signup,
    required: true
  })
  @ApiOkResponse({
    type: () => User.Safe,
    status: 200,
    description: "Returns a UserSafe."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  async register(
    @Request() request,
    @Body() credentials: IAuth.ICredentials.IWeb2.IDto.ISignup
  ): Promise<User.Safe> {
    try {
      if(!request.user) {
        return await this.web2Service.create(credentials);
      } else {
        throw new BadRequestException('you are currently logged in. Please logout to create a new account.');
      }
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }

  /**
   * Initiates password recovery process by sending reset email.
   * 
   * @param email - Email address of user requesting password reset
   * @returns Promise resolving to boolean indicating email sent status
   * @throws BadRequestException if recovery request fails
   * 
   * @description
   * Sends a password reset email to the specified user email if account exists.
   * Email contains a token for completing the password reset.
   */
  @Post('password/recovery/request')
  @ApiOperation({
    summary: 'send a password reset email to the user.',
    description: 'This endpoint is always open and does not require authentication. \
    It will send a password reset email to the user if the user exists in the database.'
  })
  @ApiOkResponse({
    type: () => Boolean,
    status: 200,
    description: "Returns a Boolean."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  @ApiQuery({
    name: 'email', 
    required: false, 
    description: 'The email of the user to send the password reset email to.'
  })
  async passwordRecoveryRequest(
    @Query('email') email?: string
  ): Promise<boolean> {
    try {
      return await this.web2Service.passwordRecoveryRequest(email);
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }

  /**
   * Completes password reset using token and new password.
   * 
   * @param token - Password reset token from email
   * @param newPassword - New password to set for user
   * @returns Promise resolving to boolean indicating reset success
   * @throws BadRequestException if reset fails
   * 
   * @description
   * Validates reset token and updates user password if token is valid.
   * Token must match one sent in password recovery email.
   */
  @Post('password/recovery/reset')
  @ApiOperation({
    summary: 'reset the password of the user.',
    description: 'This endpoint is always open and does not require authentication. \
    It will allow the user to reset the password if the user exists and the token is valid.'
  })
  @ApiOkResponse({
    type: () => Boolean,
    status: 200,
    description: "Returns a Boolean."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  @ApiQuery({
    name: 'token', 
    required: false, 
    description: 'The token of the user to reset the password of, received in the email.'
  })
  @ApiQuery({
    name: 'newPassword', 
    required: false, 
    description: 'The new password of the user.'
  })
  async passwordRecoveryReset(
    @Query('token') token?: string,
    @Query('newPassword') newPassword?: string
  ): Promise<boolean> {
    try {
      return await this.web2Service.passwordRecoveryReset(token, newPassword);
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }

  /**
   * Confirms user email address using confirmation token.
   * 
   * @param token - Email confirmation token from verification email
   * @returns Promise resolving to boolean indicating confirmation success
   * @throws BadRequestException if confirmation fails
   * 
   * @description
   * Validates email confirmation token and marks user email as verified.
   * Token must match one sent in confirmation email.
   */
  @Post('email/confirm')
  @ApiOperation({
    summary: 'confirm the email of the user.',
    description: 'This endpoint is private and does require authentication. \
    It will allow the user to confirm the email with the received token.'
  })
  @ApiOkResponse({
    type: () => Boolean,
    status: 200,
    description: "Returns a Boolean."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  @ApiQuery({
    name: 'token', 
    required: false, 
    description: 'The token to confirm the email, received in the email.'
  }) 
  async emailConfirmation(
    @Query('token') token: string
  ): Promise<boolean> {
    try {
      return await this.web2Service.emailConfirmation(token);
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }

  /**
   * Requests a new email confirmation to be sent.
   * 
   * @param request - HTTP request containing user information
   * @returns Promise resolving to boolean indicating email sent status
   * @throws BadRequestException if email already confirmed or sending fails
   * 
   * @description
   * Sends a new email confirmation if user email is not already verified.
   * Email contains token for completing verification.
   */
  @Post('email/confirm/request')
  @ApiOperation({
    summary: 'confirm the email of the user.',
    description: 'This endpoint is always open and does not require authentication. \
    It will allow the user to confirm the email if the user exists and the token is valid.'
  })
  @ApiOkResponse({
    type: () => Boolean,
    status: 200,
    description: "Returns a Boolean."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  async emailConfirmationRequest(
    @Request() request
  ): Promise<boolean> {
    try {
      if(!request.user.confirmed) {
        return await this.web2Service.sendConfirmationEmail(request.user._id, request.user.email);
      } else {
        throw new Error('The email is already confirmed');
      }
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }
}
