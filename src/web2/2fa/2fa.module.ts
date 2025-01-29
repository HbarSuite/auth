import { DynamicModule, Module } from '@nestjs/common'
import { TwoFactoryAuthService } from './2fa.service'
import { TwoFactoryAuthController } from './2fa.controller'
import { UsersModule } from '@hsuite/users'
import { _2faModuleAsyncOptions } from './interfaces/2fa-options.interface'

/**
 * Module for Two-Factor Authentication (2FA).
 * 
 * @description
 * This module provides functionality for managing two-factor authentication including:
 * - User 2FA factor creation and verification
 * - 2FA challenge generation and validation 
 * - Integration with Twilio for SMS-based 2FA
 * 
 * The module must be initialized asynchronously using forRootAsync() to configure
 * the required Twilio credentials and options.
 * 
 * @example
 * ```typescript
 * // Basic module configuration
 * @Module({
 *   imports: [
 *     TwoFactoryAuthModule.forRootAsync({
 *       imports: [ConfigModule],
 *       useFactory: (config: ConfigService) => ({
 *         accountSid: config.get('TWILIO_ACCOUNT_SID'),
 *         authToken: config.get('TWILIO_AUTH_TOKEN'),
 *         serviceSid: config.get('TWILIO_SERVICE_SID')
 *       }),
 *       inject: [ConfigService]
 *     })
 *   ]
 * })
 * export class AppModule {}
 * ```
 * 
 * @module TwoFactoryAuthModule
 * @category Authentication
 * @subcategory Two-Factor
 */
@Module({})
export class TwoFactoryAuthModule {
  /**
   * Creates a dynamic module for Two-Factor Authentication with async configuration.
   * 
   * @description
   * This method initializes the 2FA module with the provided async configuration options.
   * It sets up:
   * - The TwoFactoryAuthController for handling 2FA endpoints
   * - The TwoFactoryAuthService for 2FA business logic
   * - Integration with the UsersModule for user management
   * - Twilio configuration options for SMS delivery
   * 
   * The returned module exports TwoFactoryAuthService to make 2FA functionality
   * available to other modules.
   * 
   * @param {_2faModuleAsyncOptions} options - Async configuration options for the 2FA module
   * @returns {Promise<DynamicModule>} A dynamic module configuration with configured 2FA providers
   * 
   * @throws {Error} If required Twilio configuration options are missing or invalid
   * 
   * @example
   * ```typescript
   * // Basic usage with ConfigModule
   * TwoFactoryAuthModule.forRootAsync({
   *   imports: [ConfigModule],
   *   useFactory: (config: ConfigService) => ({
   *     accountSid: config.get('TWILIO_ACCOUNT_SID'),
   *     authToken: config.get('TWILIO_AUTH_TOKEN'),
   *     serviceSid: config.get('TWILIO_SERVICE_SID')
   *   }),
   *   inject: [ConfigService]
   * });
   * 
   * // Advanced usage with custom provider
   * TwoFactoryAuthModule.forRootAsync({
   *   imports: [ConfigModule, CustomModule],
   *   useFactory: async (config: ConfigService, custom: CustomService) => {
   *     const twilioConfig = await custom.getTwilioConfig();
   *     return {
   *       accountSid: twilioConfig.accountSid,
   *       authToken: twilioConfig.authToken,
   *       serviceSid: twilioConfig.serviceSid
   *     };
   *   },
   *   inject: [ConfigService, CustomService]
   * });
   * ```
   * 
   * @publicApi
   * @since 2.0.0
   */
  static async forRootAsync(options: _2faModuleAsyncOptions): Promise<DynamicModule> {
    return {
      module: TwoFactoryAuthModule,
      imports: [
        UsersModule // Required for user management operations
      ],
      controllers: [
        TwoFactoryAuthController // Handles 2FA HTTP endpoints
      ],
      providers: [
        {
          provide: 'twilioOptions', // Injection token for Twilio config
          useValue: options // Async options for Twilio setup
        },
        TwoFactoryAuthService // Core 2FA service
      ],
      exports: [
        TwoFactoryAuthService // Make 2FA service available to other modules
      ]
    }
  }    
}
