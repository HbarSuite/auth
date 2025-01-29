import { Body, Controller, Get, Post, Res, Request, UseGuards, BadRequestException, Inject} from '@nestjs/common'
import { AuthWeb2Service } from './web2.service'
import * as moment from 'moment'
import { ApiBadRequestResponse, ApiBody, ApiNotFoundResponse, ApiOkResponse, ApiOperation, ApiTags } from '@hsuite/nestjs-swagger'
import { IAuth, Auth } from '@hsuite/auth-types'
import { Web2AuthGuard } from '../guards/web2.guard'

/**
 * Controller for handling Web2 authentication sessions.
 * 
 * @description
 * This controller manages user authentication sessions including:
 * - User login with email/password
 * - Session creation and management
 * - User logout and session destruction
 * - Cookie management for JWT or session-based auth
 * 
 * It supports both JWT and session-based authentication strategies
 * configured through authWeb2Options.
 */
@Controller('auth/web2')
@ApiTags('auth/web2')
export class AuthWeb2SessionController {
  /**
   * Creates an instance of AuthWeb2SessionController.
   * 
   * @param authWeb2Options - Configuration options for Web2 authentication
   * @param web2Service - Service handling Web2 authentication logic
   */
  constructor(
    @Inject('authWeb2Options') private authWeb2Options: IAuth.IConfiguration.IWeb2.IOptions & IAuth.IConfiguration.IOptions,
    private readonly web2Service: AuthWeb2Service
  ) {}

  /**
   * Handles user login requests.
   * 
   * @param credentials - User login credentials containing email/username and password
   * @param response - HTTP response object for setting cookies
   * @returns Promise resolving to login response with user info and access token
   * @throws BadRequestException if login fails
   * 
   * @description
   * Authenticates user credentials and:
   * 1. Creates a new session
   * 2. Sets appropriate cookies based on auth strategy
   * 3. Returns user info and access token
   */
  @UseGuards(Web2AuthGuard)
  @Post('login')
  @ApiOperation({
    summary: 'allow a user to login with email/username and password.',
    description: 'This endpoint is always open and does not require authentication. \
    it will though check the existence of the user in the database and the validity of the credentials. \
    If the user exists and the credentials are valid, a session will be created.'
  })
  @ApiOkResponse({
    type: () => Auth.Credentials.Web2.Response.Login,
    status: 200,
    description: "Returns a Auth.Credentials.Web2.Response.Login."
  }) 
  @ApiBody({
    type: () => Auth.Credentials.Web2.Dto.Login,
    required: true
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  async login(
    @Body() credentials: IAuth.ICredentials.IWeb2.IDto.ILogin,
    @Res({passthrough: true}) response
  ): Promise<IAuth.ICredentials.IWeb2.IResponse.ILogin> {
    try {
      // Attempt login and get auth response
      let authLogin = await this.web2Service.login(credentials);

      // Set cookies if using JWT strategy
      if(
        this.authWeb2Options.passport == IAuth.IConfiguration.IPassportStrategy.JWT
      ) {
        response.cookie(
          'accessToken', 
          authLogin.accessToken,
          {
            expires:  moment().add(this.authWeb2Options.jwt.signOptions.expiresIn, 'hour').toDate()
          }
        );
      }
  
      return authLogin;
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }

  /**
   * Handles user logout requests.
   * 
   * @param request - HTTP request object containing session info
   * @param response - HTTP response object for clearing cookies
   * @returns Promise resolving to logout confirmation
   * @throws BadRequestException if logout fails
   * 
   * @description
   * Logs out user by:
   * 1. Clearing auth cookies
   * 2. Destroying session if using session-based auth
   * 3. Returning logout confirmation
   */
  @Get('/logout')
  @ApiOperation({
    summary: 'allow a user to logout and destroy the session.',
    description: 'This endpoint is protected and requires authentication. \
    It will destroy the session and the user will be logged out.'
  })
  @ApiOkResponse({
    type: () => Auth.Credentials.Web2.Response.Logout,
    status: 200,
    description: "Returns a CredentialsLogoutResponse."
  }) 
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  async logout(
    @Request() request,
    @Res({passthrough: true}) response
  ): Promise<IAuth.ICredentials.IWeb2.IResponse.ILogout> {
    try {
      // Handle JWT logout
      if(
        this.authWeb2Options.passport == IAuth.IConfiguration.IPassportStrategy.JWT
      ) {
        response.cookie(
          'accessToken', 
          null,
          {
            expires:  moment().toDate()
          }
        );
      } 
      // Handle session-based logout
      else {
        request.session.destroy();
        
        response.cookie(
          'connect.sid', 
          null,
          {
            expires:  moment().toDate()
          }
        );
      }
  
      return {
        logout: true,
        message: 'The user session has ended'
      }
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }
}
