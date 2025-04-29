import { IAuth, Auth } from '@hsuite/auth-types'
import { UserDocument, UsersService } from '@hsuite/users'
import { User } from '@hsuite/users-types'
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common'
import { MailerService } from '@nestjs-modules/mailer'
import * as bcrypt from 'bcrypt'
import * as moment from 'moment'
import * as lodash from 'lodash'
import { LoggerHelper } from '@hsuite/helpers/logger.helper'

/**
 * Service responsible for handling authentication-related operations for Web2 users.
 * 
 * @description
 * This service provides functionality for:
 * - User authentication and validation
 * - Account creation and management
 * - Password recovery and reset
 * - Email confirmation
 * - User login and token generation
 * 
 * It integrates with the following services:
 * - UsersService for user data management
 * - MailerService for sending emails
 * - JwtService for token operations
 */
@Injectable()
export class AuthWeb2Service {
    /**
     * Logger instance for the service
     * @type {LoggerHelper}
     */
    protected logger: LoggerHelper = new LoggerHelper(AuthWeb2Service.name);

    /**
     * Creates an instance of AuthWeb2Service.
     * 
     * @param authWeb2Options - Configuration options for Web2 authentication
     * @param jwtService - Service for JWT operations
     * @param usersService - Service for user-related operations
     * @param mailerService - Service for sending emails
     */
    constructor(
        @Inject('authWeb2Options') private authWeb2Options: IAuth.IConfiguration.IWeb2.IOptions & IAuth.IConfiguration.IOptions,
        @Inject('JwtAuthService') private readonly jwtService,
        private usersService: UsersService,
        private readonly mailerService: MailerService
    ) { }

    /**
     * Validates a user's credentials.
     * 
     * @param user - User credentials to validate
     * @returns Promise resolving to UserSafe object if validation successful, null otherwise
     * 
     * @description
     * Validates user credentials by:
     * 1. Finding user in database
     * 2. Comparing provided password with stored hash
     * 3. Returning safe user object without password if valid
     */
    async validateUser(
        user: Auth.Credentials.Web2.Dto.Signup
    ): Promise<User.Safe | null> {
        return new Promise(async (resolve, reject) => {
            try {
                // Find user document by credentials
                const userDocument = await this.usersService.find(user);

                if (
                    userDocument &&
                    (await bcrypt.compare(user.password, userDocument.password))
                ) {
                    const { password, ...result } = userDocument;
                    resolve(result);
                } else {
                    resolve(null);
                }
            } catch (error) {
                reject(error);
            }
        })
    }

    /**
     * Sends a confirmation email to a user.
     * 
     * @param userId - The ID of the user
     * @param userEmail - The email address of the user
     * @returns Promise resolving to true if email sent successfully
     * 
     * @description
     * Sends confirmation email by:
     * 1. Generating JWT token with user ID
     * 2. Preparing email template with token
     * 3. Sending email via mailer service
     */
    async sendConfirmationEmail(
        userId: string,
        userEmail: string
    ): Promise<boolean> {
        return new Promise(async(resolve, reject) => {
            try {
                // Generate confirmation token
                let accessToken = this.jwtService.sign({
                    userId: userId,
                    type: 'email_confirmation'
                });

                // Prepare email options
                let sendMailOptions = lodash.cloneDeep(this.authWeb2Options.sendMailOptions);
                sendMailOptions.confirm.to = userEmail;

                // Replace token placeholder in templates
                sendMailOptions.confirm.text =
                    (<string>this.authWeb2Options.sendMailOptions.confirm.text).replace(
                        'PLACE_HOLDER_FOR_TOKEN',
                        accessToken
                    );

                sendMailOptions.confirm.html =
                    (<string>this.authWeb2Options.sendMailOptions.confirm.html).replace(
                        'PLACE_HOLDER_FOR_TOKEN',
                        accessToken
                    );

                await this.mailerService.sendMail(sendMailOptions.confirm);
                resolve(true);
            } catch(error) {
                reject(error);
            }
        })
    }

    /**
     * Creates a new user account.
     * 
     * @param user - User information for account creation
     * @returns Promise resolving to UserSafe object of created user
     * 
     * @description
     * Creates new user by:
     * 1. Creating user document with default values
     * 2. Sending confirmation email if required
     * 3. Returning safe user object without password
     */
    async create(user: Auth.Credentials.Web2.Dto.Signup): Promise<User.Safe> {
        return new Promise(async (resolve, reject) => {
            try {
                // Create new user with default values
                const web2User = await this.usersService.create({
                    ...user,
                    created_at: moment().unix(),
                    updated_at: moment().unix(),
                    confirmed: false,
                    type: IAuth.ICredentials.IUser.IType.WEB2,
                    role: 'user',
                    banned: false,
                    twoFactorAuth: {
                        status: IAuth.ITwoFactor.IStatus.DISABLED,
                        factorSid: '',
                        identity: '',
                        qr_code: ''
                    },
                });

                // Send confirmation email if required
                if(this.authWeb2Options.confirmation_required) {
                    try {
                        await this.sendConfirmationEmail(
                            <string> web2User._id,
                            user.email
                        )
                    } catch(error) {
                        this.logger.error(error.message)
                    }
                }

                const { password, ...newUser } = web2User;
                resolve(newUser);
            } catch (error) {
                reject(error);
            }
        })
    }

    /**
     * Initiates a password recovery request for a user.
     * 
     * @param email - Email address of user requesting recovery
     * @returns Promise resolving to true if request successful
     * 
     * @description
     * Handles password recovery by:
     * 1. Finding user by email
     * 2. Generating recovery token
     * 3. Sending recovery email with token
     */
    async passwordRecoveryRequest(email: string): Promise<boolean> {
        return new Promise(async (resolve, reject) => {
            try {
                // Find user by email
                let userDocument: UserDocument = await this.usersService.find({
                    email: email,
                    username: null,
                    password: null
                });

                if (!userDocument) {
                    throw new Error('User not found');
                }

                // Generate recovery token
                let accessToken = this.jwtService.sign({
                    userId: userDocument._id,
                    type: 'password_recovery'
                });

                // Prepare and send recovery email
                let sendMailOptions = lodash.cloneDeep(this.authWeb2Options.sendMailOptions);
                sendMailOptions.reset.to = email;

                sendMailOptions.reset.text =
                    (<string>this.authWeb2Options.sendMailOptions.reset.text).replace(
                        'PLACE_HOLDER_FOR_TOKEN',
                        accessToken
                    );

                sendMailOptions.reset.html =
                    (<string>this.authWeb2Options.sendMailOptions.reset.html).replace(
                        'PLACE_HOLDER_FOR_TOKEN',
                        accessToken
                    );

                await this.mailerService.sendMail(sendMailOptions.reset);
                resolve(true);
            } catch (error) {
                reject(error);
            }
        })
    }

    /**
     * Resets a user's password using a recovery token.
     * 
     * @param token - Password recovery token
     * @param newPassword - New password to set
     * @returns Promise resolving to true if password reset successful
     * 
     * @description
     * Resets password by:
     * 1. Verifying recovery token
     * 2. Finding user from token payload
     * 3. Updating password in database
     */
    async passwordRecoveryReset(token: string, newPassword: string): Promise<boolean> {
        return new Promise(async (resolve, reject) => {
            try {
                // Verify token and get payload
                let payload = this.jwtService.verify(token);
                let userDocument: UserDocument = await this.usersService.findById(payload.userId);

                if (!userDocument) {
                    throw new Error('User not found');
                }

                if (payload.type != 'password_recovery') {
                    throw new UnauthorizedException('Invalid token')
                }

                // Update password
                await this.usersService.updatePassword(
                    userDocument.email,
                    newPassword
                );

                resolve(true);
            } catch (error) {
                reject(error);
            }
        })
    }

    /**
     * Confirms a user's email address using a confirmation token.
     * 
     * @param token - Email confirmation token
     * @returns Promise resolving to true if email confirmed successfully
     * 
     * @description
     * Confirms email by:
     * 1. Verifying confirmation token
     * 2. Finding user from token payload
     * 3. Updating user's email confirmation status
     */
    async emailConfirmation(token: string): Promise<boolean> {
        return new Promise(async (resolve, reject) => {
            try {
                // Verify token and get payload
                let payload = this.jwtService.verify(token);
                let userDocument: UserDocument = await this.usersService.findById(payload.userId);

                if (!userDocument) {
                    throw new Error('User not found');
                }

                if (payload.type != 'email_confirmation') {
                    throw new Error('Invalid token');
                }

                // Confirm email
                await this.usersService.emailConfirmation(
                    payload.userId
                );

                resolve(true);
            } catch (error) {
                reject(error);
            }
        })
    }

    /**
     * Logs in a user and generates an access token.
     * 
     * @param user - User login credentials
     * @returns Promise resolving to login response with user info and access token
     * 
     * @description
     * Handles login by:
     * 1. Finding and validating user
     * 2. Generating access token
     * 3. Returning user info and operator details
     */
    async login(user: IAuth.ICredentials.IWeb2.IDto.ILogin): Promise<IAuth.ICredentials.IWeb2.IResponse.ILogin> {
        const smartNodeUser: UserDocument = await this.usersService.find(user);
        const { password, ...userSafe } = smartNodeUser;

        return {
            user: userSafe,
            operator: {
                accountId: this.authWeb2Options.operator.accountId,
                publicKey: this.authWeb2Options.operator.publicKey.toString(),
                url: this.authWeb2Options.operator.url,
                nft: {
                    id: null,
                    serialNumber: null
                }
            },
            accessToken: this.jwtService.sign(userSafe)
        };
    }
}
