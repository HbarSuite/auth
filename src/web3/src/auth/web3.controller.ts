import { BadRequestException, Body, Controller, Get, Inject, Post, Req, Request, Res, UseGuards } from '@nestjs/common'
import { AuthWeb3Service } from './web3.service'
import { ApiBadRequestResponse, ApiBody, ApiNotFoundResponse, ApiOkResponse, ApiOperation, ApiTags } from '@hsuite/nestjs-swagger'
import * as moment from 'moment'
import { Web3AuthGuard } from '../guards/web3.guard'
import { CacheTTL } from '@nestjs/cache-manager'
import { Public, Auth, IAuth } from '@hsuite/auth-types'

/**
 * Controller for handling Web3 authentication-related operations.
 * 
 * @description
 * This controller provides endpoints for Web3 wallet-based authentication including:
 * - Generating authentication requests to be signed by Web3 wallets
 * - Processing signed payloads for user login
 * - Managing user sessions and logout
 * 
 * @example
 * ```typescript
 * // Generate auth request
 * GET /auth/web3/request
 * 
 * // Login with signed payload
 * POST /auth/web3/login
 * 
 * // Logout user
 * GET /auth/web3/logout
 * ```
 */
@Controller('auth/web3')
@ApiTags('auth/web3')
export class AuthWeb3Controller {

  /**
   * Creates an instance of AuthWeb3Controller.
   * 
   * @param authWeb3Options - Configuration options for Web3 authentication
   * @param web3Service - Service handling Web3 authentication logic
   */
  constructor(
    @Inject('authWeb3Options') private authWeb3Options: IAuth.IConfiguration.IWeb3.IOptions & IAuth.IConfiguration.IOptions,
    private readonly web3Service: AuthWeb3Service,
  ) {}

  /**
   * Generates a request payload to be signed offline with a Web3 wallet.
   * 
   * @description
   * This endpoint:
   * 1. Generates a unique token
   * 2. Creates a payload with site URL, node ID and token
   * 3. Signs the payload with the service's private key
   * 4. Returns both signed data and original payload
   * 
   * @param request - The incoming request object
   * @returns Promise resolving to authentication request payload
   * @throws BadRequestException if payload generation fails
   */
  @Get('request')
  @Public()
  @CacheTTL(1)
  @ApiOperation({
    summary: 'trigger a request to be signed offline with your web3 wallet.',
    description: 'This endpoint will return a payload to be signed offline with your web3 wallet. \
    The signed payload will then be sent to the login endpoint to authenticate the user.'
  })
  @ApiOkResponse({
    type: () => Auth.Credentials.Web3.Request.Authentication.Authenticate,
    status: 200,
    description: "Returns a Web3AuthRequestDto."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  async request(
    @Request() request
  ): Promise<Auth.Credentials.Web3.Request.Authentication.Authenticate> {
    try {
      // Create authentication payload with site info and token
      let payload: IAuth.ICredentials.IWeb3.IRequest.IAuthentication.IPayload = {
        url: 'https://hbarsuite.app',
        node: this.web3Service.getOperatorId(),
        data: {
          token: this.web3Service.generateToken()  
        }
      };
    
      // Sign the payload with service private key
      let signedData: IAuth.ICredentials.IWeb3.IRequest.IAuthentication.ISignedData = 
        this.web3Service.signData(payload);
    
      // Combine signed data and original payload
      let authenticateRequest: Auth.Credentials.Web3.Request.Authentication.Authenticate = {
        signedData: signedData,
        payload: payload
      };

      return authenticateRequest;
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }

  /**
   * Authenticates a user using a Web3 signed payload.
   * 
   * @description
   * This endpoint:
   * 1. Validates the signed payload via Web3AuthGuard
   * 2. Creates user session using web3Service
   * 3. Sets appropriate cookies based on auth strategy
   * 
   * @param credentials - Login credentials with signed payload
   * @param response - Response object for cookie management
   * @param request - Request object containing authenticated user
   * @returns Promise resolving to login response
   * @throws BadRequestException if login fails
   */
  @UseGuards(Web3AuthGuard)
  @Post('login')
  @ApiOperation({
    summary: 'create a user session from a web3 signed payload.',
    description: 'This endpoint will create a user session from a web3 signed payload. \
    The payload must be signed offline with your web3 wallet.'
  })
  @ApiBody({
    type: () => Auth.Credentials.Web3.Request.Signin.Login,
    description: "The signed payload from the request endpoint."
  })
  @ApiOkResponse({
    type: () => Auth.Credentials.Web3.Request.Signin.Login,
    status: 200,
    description: "Returns a Auth.Credentials.Web3.Request.Signin.Login."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  async login(
    @Body() credentials: IAuth.ICredentials.IWeb3.IRequest.ISignin.ILogin,
    @Res({passthrough: true}) response,
    @Request() request,
  ): Promise<IAuth.ICredentials.IWeb3.IResponse.ILogin> {
    try {
      let authLogin = await this.web3Service.login(request.user, credentials);
      
      // Set JWT cookie if using JWT strategy
      if(
        this.authWeb3Options.passport == IAuth.IConfiguration.IPassportStrategy.JWT
      ) {
        response.cookie(
          'accessToken', 
          authLogin.accessToken,
          {
            expires:  moment().add(this.authWeb3Options.jwt.signOptions.expiresIn, 'hour').toDate()
          }
        );
      }
  
      return authLogin;
    } catch(error) {
      throw new BadRequestException(error.message);
    }
  }

  /**
   * Logs out the user by destroying the session.
   * 
   * @description
   * This endpoint:
   * 1. Destroys the user session
   * 2. Clears authentication cookies
   * 3. Returns logout confirmation
   * 
   * Handles both JWT and session-based authentication strategies.
   * 
   * @param request - Request object for session management
   * @param response - Response object for cookie management
   * @returns Promise resolving to logout response
   * @throws BadRequestException if logout fails
   */
  @Get('/logout')
  @ApiOperation({
    summary: 'allow a user to logout and destroy the session.',
    description: 'This endpoint will destroy the session and the user will be logged out. \
    This endpoint is protected and requires authentication.'
  })
  @ApiOkResponse({
    type: () => Auth.Credentials.Web3.Response.Logout,
    status: 200,
    description: "Returns a CredentialsLogoutResponse."
  })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  async logout(
    @Request() request,
    @Res({passthrough: true}) response
  ): Promise<IAuth.ICredentials.IWeb3.IResponse.ILogout> {
    try {
      // Handle JWT logout
      if(
        this.authWeb3Options.passport == IAuth.IConfiguration.IPassportStrategy.JWT
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
