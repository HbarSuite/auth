import { IAuth } from '@hsuite/auth-types'
import { ModuleMetadata, Type } from '@nestjs/common/interfaces';

/**
 * Interface defining the factory for creating Two-Factor Authentication (2FA) options.
 * 
 * @description
 * This interface provides the contract for factories that create 2FA configuration options.
 * It defines the required method for generating Twilio-based 2FA settings.
 *
 * @interface
 * @public
 *
 * @example
 * ```typescript
 * class Custom2FAFactory implements _2faOptionsFactory {
 *   async create_2faOptions(): Promise<IAuth.ITwilio.IOptions> {
 *     return {
 *       accountSid: 'your_account_sid',
 *       authToken: 'your_auth_token',
 *       serviceSid: 'your_service_sid'
 *     };
 *   }
 * }
 * ```
 */
export interface _2faOptionsFactory {
    /**
     * Creates and returns the 2FA authentication options.
     * 
     * @description
     * This method is responsible for generating the Twilio configuration options
     * needed for 2FA functionality. It can return the options either synchronously
     * or as a Promise.
     * 
     * @returns {Promise<IAuth.ITwilio.IOptions> | IAuth.ITwilio.IOptions} The Twilio configuration options containing accountSid, authToken and serviceSid
     * 
     * @example
     * ```typescript
     * // Synchronous implementation
     * create_2faOptions(): IAuth.ITwilio.IOptions {
     *   return {
     *     accountSid: process.env.TWILIO_ACCOUNT_SID,
     *     authToken: process.env.TWILIO_AUTH_TOKEN,
     *     serviceSid: process.env.TWILIO_SERVICE_SID
     *   };
     * }
     * 
     * // Asynchronous implementation
     * async create_2faOptions(): Promise<IAuth.ITwilio.IOptions> {
     *   const config = await loadConfig();
     *   return {
     *     accountSid: config.twilioAccountSid,
     *     authToken: config.twilioAuthToken,
     *     serviceSid: config.twilioServiceSid
     *   };
     * }
     * ```
     */
    create_2faOptions(): Promise<IAuth.ITwilio.IOptions> | IAuth.ITwilio.IOptions;
}

/**
 * Interface for asynchronous 2FA options configuration.
 * 
 * @description
 * This interface extends the NestJS ModuleMetadata to provide async configuration
 * options for the 2FA module. It supports different patterns for providing options:
 * useExisting, useClass, or useFactory.
 *
 * @interface
 * @extends {Pick<ModuleMetadata, 'imports'>}
 * @public
 *
 * @example
 * ```typescript
 * // Using useFactory
 * const asyncConfig: _2faModuleAsyncOptions = {
 *   imports: [ConfigModule],
 *   useFactory: async (configService: ConfigService) => ({
 *     accountSid: configService.get('TWILIO_ACCOUNT_SID'),
 *     authToken: configService.get('TWILIO_AUTH_TOKEN'),
 *     serviceSid: configService.get('TWILIO_SERVICE_SID')
 *   }),
 *   inject: [ConfigService]
 * };
 * 
 * // Using useClass
 * const asyncConfig: _2faModuleAsyncOptions = {
 *   useClass: TwilioConfigService
 * };
 * 
 * // Using useExisting
 * const asyncConfig: _2faModuleAsyncOptions = {
 *   useExisting: [ExistingTwilioConfigService]
 * };
 * ```
 */
export interface _2faModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
    /**
     * An existing _2faOptionsFactory type to be used.
     * 
     * @description
     * References an existing factory class that implements _2faOptionsFactory.
     * This allows reusing an existing factory that's already available in the dependency injection container.
     * 
     * @example
     * ```typescript
     * // Define existing factory
     * @Injectable()
     * class ExistingTwilioFactory implements _2faOptionsFactory {
     *   create_2faOptions() {
     *     return {
     *       accountSid: 'sid',
     *       authToken: 'token',
     *       serviceSid: 'service'
     *     };
     *   }
     * }
     * 
     * // Use in module config
     * {
     *   useExisting: [ExistingTwilioFactory]
     * }
     * ```
     */
    useExisting?: Array<Type<any>>;

    /**
     * A class to be instantiated as a _2faOptionsFactory.
     * 
     * @description
     * Specifies a class that will be instantiated to create the options factory.
     * The class must implement the _2faOptionsFactory interface.
     * 
     * @example
     * ```typescript
     * // Define factory class
     * @Injectable()
     * class TwilioConfigFactory implements _2faOptionsFactory {
     *   create_2faOptions() {
     *     return {
     *       accountSid: 'sid',
     *       authToken: 'token',
     *       serviceSid: 'service'
     *     };
     *   }
     * }
     * 
     * // Use in module config
     * {
     *   useClass: TwilioConfigFactory
     * }
     * ```
     */
    useClass?: Type<any>;

    /**
     * A factory function that returns 2FA configuration options.
     * 
     * @description
     * A factory function that generates the 2FA configuration options.
     * Can be synchronous or asynchronous. Useful for dynamic configuration
     * based on injected dependencies.
     * 
     * @param {...any[]} args - Dependencies that will be injected into the factory function
     * @returns {Promise<IAuth.ITwilio.IOptions> | IAuth.ITwilio.IOptions} The Twilio configuration options
     * 
     * @example
     * ```typescript
     * // Synchronous factory
     * {
     *   useFactory: (config: ConfigService) => ({
     *     accountSid: config.get('TWILIO_ACCOUNT_SID'),
     *     authToken: config.get('TWILIO_AUTH_TOKEN'),
     *     serviceSid: config.get('TWILIO_SERVICE_SID')
     *   }),
     *   inject: [ConfigService]
     * }
     * 
     * // Asynchronous factory
     * {
     *   useFactory: async (config: ConfigService) => {
     *     const settings = await config.loadTwilioSettings();
     *     return {
     *       accountSid: settings.accountSid,
     *       authToken: settings.authToken,
     *       serviceSid: settings.serviceSid
     *     };
     *   },
     *   inject: [ConfigService]
     * }
     * ```
     */
    useFactory?: (...args: any[]) => Promise<IAuth.ITwilio.IOptions> | IAuth.ITwilio.IOptions;

    /**
     * Optional list of providers to be injected into the context of the Factory function.
     * 
     * @description
     * Specifies the dependencies that should be injected into the factory function.
     * These providers must be available in the module's context.
     * 
     * @example
     * ```typescript
     * {
     *   useFactory: (config: ConfigService, http: HttpService) => ({
     *     accountSid: config.get('TWILIO_ACCOUNT_SID'),
     *     authToken: config.get('TWILIO_AUTH_TOKEN'),
     *     serviceSid: config.get('TWILIO_SERVICE_SID')
     *   }),
     *   inject: [ConfigService, HttpService]
     * }
     * ```
     */
    inject?: any[];
}