import { Inject, Injectable } from '@nestjs/common'
import { UserDocument, UsersService } from '@hsuite/users'
const { v4: uuidv4 } = require('uuid')
import { Twilio } from 'twilio'
import { IAuth } from '@hsuite/auth-types'

/**
 * Service for handling Two-Factor Authentication (2FA) operations.
 * 
 * @description
 * This service provides functionality for managing two-factor authentication including:
 * - Creating and verifying 2FA factors
 * - Checking 2FA status for users
 * - Generating and validating 2FA challenges
 * - Managing Twilio integration for TOTP-based 2FA
 * 
 * The service integrates with Twilio's Verify API for secure factor management
 * and with the UsersService for persisting 2FA state.
 */
@Injectable()
export class TwoFactoryAuthService {
    /** 
     * Twilio client instance for API calls 
     * @private
     */
    private client: Twilio;

    /**
     * Creates an instance of TwoFactoryAuthService.
     * 
     * @param usersService - The UsersService for user-related operations
     * @param twilioOptions - The Twilio configuration options
     * 
     * @description
     * Initializes the service with required dependencies and sets up the Twilio client
     * using provided credentials.
     */
    constructor(
        private usersService: UsersService,
        @Inject('twilioOptions') private twilioOptions: IAuth.ITwilio.IOptions
    ) {
        // Initialize Twilio client with credentials
        this.client = require('twilio')(
            this.twilioOptions.twilioSecrets.accountSid, 
            this.twilioOptions.twilioSecrets.authToken
        );
    }

    /**
     * Checks if Two-Factor Authentication is enabled for a user.
     * 
     * @param userId - The ID of the user to check
     * @returns Promise resolving to boolean indicating if 2FA is enabled
     * @throws {Error} If user not found or operation fails
     * 
     * @description
     * Verifies if a user has completed 2FA setup and verification.
     * Returns true only if 2FA status is 'verified'.
     * 
     * @example
     * ```typescript
     * try {
     *   const is2FAEnabled = await service.isEnabled('user123');
     *   console.log('2FA Status:', is2FAEnabled);
     * } catch (error) {
     *   console.error('Failed to check 2FA status:', error);
     * }
     * ```
     */
    async isEnabled(
        userId: string
    ): Promise<boolean> {
        return new Promise(async(resolve, reject) => {
            try {
                let userDocument: UserDocument = await this.usersService.findById(userId);

                if (!userDocument) {
                    reject(new Error('User not found'));
                }

                if(userDocument.twoFactorAuth.status === 'verified') {
                    resolve(true);
                }

                resolve(false);
            } catch(error) {
                reject(error);
            }
        })
    }

    /**
     * Creates a new Two-Factor Authentication factor for a user.
     * 
     * @param userId - The ID of the user to create the factor for
     * @returns Promise resolving to created factor details including QR code
     * @throws {Error} If user not found or 2FA already enabled
     * 
     * @description
     * Creates a new TOTP factor through Twilio Verify API.
     * Generates QR code for authenticator app setup.
     * Updates user document with new factor details.
     * 
     * @example
     * ```typescript
     * try {
     *   const factor = await service.createFactor('user123');
     *   console.log('QR Code URI:', factor.uri);
     *   console.log('Secret Key:', factor.secret);
     * } catch (error) {
     *   console.error('Failed to create 2FA factor:', error);
     * }
     * ```
     */
    async createFactor(
        userId: string
    ): Promise<IAuth.ITwoFactor.IResponse.ICreate> {
        return new Promise(async (resolve, reject) => {
            try {
                let userDocument: UserDocument = await this.usersService.findById(userId);

                if (!userDocument) {
                    reject(new Error('User not found'));
                }

                if(userDocument.twoFactorAuth.status === 'verified') {
                    reject(new Error('2FA already enabled.'));
                }

                if(userDocument.twoFactorAuth.status === 'unverified') {
                    reject(new Error('2FA already enabled, but not verified.'));
                }

                // Generate unique identity for Twilio entity
                let identity = uuidv4();

                // Create new TOTP factor via Twilio
                let factor = await this.client.verify.v2
                    .services(this.twilioOptions.twilioSecrets.serviceSid)
                    .entities(identity)
                    .newFactors
                    .create({
                        friendlyName: userDocument.email,
                        factorType: 'totp'
                    });

                // Prepare 2FA data for user document
                let twoFactorAuth: IAuth.ITwoFactor.IAuth = {
                    status: IAuth.ITwoFactor.IStatus.UNVERIFIED,
                    identity: identity,
                    factorSid: factor.sid,
                    qr_code: factor.binding.uri
                };

                // Update user's 2FA information
                await this.usersService.updateTwoFactorAuth(userId, twoFactorAuth);                    

                let response = {
                    factorSid: factor.sid,
                    identity,
                    uri: factor.binding.uri,
                    secret: factor.binding.secret,
                    message: `Please scan the QR code in an authenticator app like Authy.`,
                }

                resolve(response);
            } catch (error) {
                reject(error);
            }
        })
    }

    /**
     * Deletes the Two-Factor Authentication factor for a user.
     * 
     * @param code - The verification code provided by the user
     * @param userId - The ID of the user to delete the factor for
     * @returns Promise resolving to deletion confirmation
     * @throws {Error} If user not found, code invalid, or 2FA already disabled
     * 
     * @description
     * Verifies provided code before deletion.
     * Removes factor from Twilio and updates user document.
     * 
     * @example
     * ```typescript
     * try {
     *   const result = await service.deleteFactor('123456', 'user123');
     *   console.log('2FA Deletion:', result.message);
     * } catch (error) {
     *   console.error('Failed to delete 2FA:', error);
     * }
     * ```
     */
    async deleteFactor(
        code: string,
        userId: string
    ): Promise<IAuth.ITwoFactor.IResponse.IDelete> {
        return new Promise(async (resolve, reject) => {
            try {
                let userDocument: UserDocument = await this.usersService.findById(userId);

                if (!userDocument) {
                    reject(new Error('User not found'));
                }

                if(userDocument.twoFactorAuth.status === 'disabled') {
                    reject(new Error('2FA already disabled.'));
                }

                // Verify code before deletion
                try {
                    await this.createChallenge(userId, code);
                } catch(error) {
                    reject(error);
                }

                // Remove factor from Twilio
                await this.client.verify.v2
                    .services(this.twilioOptions.twilioSecrets.serviceSid)
                    .entities(userDocument.twoFactorAuth.identity)
                    .factors(userDocument.twoFactorAuth.factorSid)
                    .remove();

                // Reset user's 2FA status
                let twoFactorAuth: IAuth.ITwoFactor.IAuth = {
                    status: IAuth.ITwoFactor.IStatus.DISABLED,
                    identity: '',
                    factorSid: '',
                    qr_code: ''
                };

                await this.usersService.updateTwoFactorAuth(userId, twoFactorAuth);                    

                let response = {
                    success: true,
                    message: `Your 2FA has been disabled.`,
                }

                resolve(response);
            } catch (error) {
                reject(error);
            }
        })
    }

    /**
     * Verifies the Two-Factor Authentication factor for a user.
     * 
     * @param userId - The ID of the user to verify the factor for
     * @param code - The verification code provided by the user
     * @returns Promise resolving to verification result
     * @throws {Error} If user not found or code invalid
     * 
     * @description
     * Validates provided code against Twilio factor.
     * Updates user's 2FA status to verified on success.
     * 
     * @example
     * ```typescript
     * try {
     *   const result = await service.verifyFactor('user123', '123456');
     *   console.log('Verification:', result.message);
     * } catch (error) {
     *   console.error('Failed to verify 2FA:', error);
     * }
     * ```
     */
    async verifyFactor(
        userId: string,
        code: string
    ): Promise<IAuth.ITwoFactor.IResponse.IVerify> {
        return new Promise(async(resolve, reject) => {
            try {
                let userDocument: UserDocument = await this.usersService.findById(userId);

                if (!userDocument) {
                    reject(new Error('User not found'));
                }

                // Verify factor with Twilio
                let checkedFactor = await this.client.verify.v2
                    .services(this.twilioOptions.twilioSecrets.serviceSid)
                    .entities(userDocument.twoFactorAuth.identity)
                    .factors(userDocument.twoFactorAuth.factorSid)
                    .update({ authPayload: code });

                if (checkedFactor.status !== IAuth.ITwoFactor.IStatus.VERIFIED) {
                    throw new Error('Incorrect code.');
                }

                // Update user's 2FA status to verified
                userDocument.twoFactorAuth.status = IAuth.ITwoFactor.IStatus.VERIFIED;
                await this.usersService.updateTwoFactorAuth(
                    userId, userDocument.twoFactorAuth
                );

                resolve({
                    success: true,
                    message: 'Factor verified.',
                });
            } catch (error) {
                reject(error);
            }
        })
    }

    /**
     * Creates a challenge for Two-Factor Authentication verification.
     * 
     * @param userId - The ID of the user to create the challenge for
     * @param code - The verification code provided by the user
     * @returns Promise resolving to challenge verification result
     * @throws {Error} If user not found or code invalid
     * 
     * @description
     * Creates and immediately verifies a challenge through Twilio.
     * Used for validating 2FA codes during authentication.
     * 
     * @example
     * ```typescript
     * try {
     *   const result = await service.createChallenge('user123', '123456');
     *   console.log('Challenge:', result.message);
     * } catch (error) {
     *   console.error('Failed to verify challenge:', error);
     * }
     * ```
     */
    async createChallenge(
        userId: string,
        code: string
    ): Promise<IAuth.ITwoFactor.IResponse.IVerify> {
        return new Promise(async(resolve, reject) => {
            try {
                let userDocument: UserDocument = await this.usersService.findById(userId);

                if (!userDocument) {
                    reject(new Error('User not found'));
                }

                // Create and verify challenge with Twilio
                let challenge = await this.client.verify.v2
                    .services(this.twilioOptions.twilioSecrets.serviceSid)
                    .entities(userDocument.twoFactorAuth.identity)
                    .challenges
                    .create({ 
                        authPayload: code,
                        factorSid: userDocument.twoFactorAuth.factorSid
                    });

                if (challenge.status !== 'approved') {
                    throw new Error('Incorrect code.');
                }

                resolve({
                    success: true,
                    message: 'Verification success.',
                });
            } catch (error) {
                reject(error);
            }
        })
    }
}
