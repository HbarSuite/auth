import { IAuth } from '@hsuite/auth-types'
import { ModuleMetadata, Type } from '@nestjs/common/interfaces';

/**
 * Factory interface for creating authentication configuration options.
 * 
 * @interface AuthenticationOptionsFactory
 * @description
 * This factory pattern enables dynamic configuration of authentication settings
 * by providing a standardized way to create authentication options at runtime.
 * 
 * Implementations can provide different authentication configurations based on:
 * - Environment variables
 * - External configuration services
 * - Dynamic runtime conditions
 * 
 * @example
 * ```typescript
 * class CustomAuthOptionsFactory implements AuthenticationOptionsFactory {
 *   createAuthenticationOptions(): Promise<IAuth.IConfiguration.IAuthentication> {
 *     return {
 *       commonOptions: {
 *         jwt: { secret: process.env.JWT_SECRET },
 *         passport: 'jwt'
 *       }
 *     };
 *   }
 * }
 * ```
 */
export interface AuthenticationOptionsFactory {
    /**
     * Creates authentication configuration options.
     * 
     * @description
     * Method to generate authentication configuration either synchronously or asynchronously.
     * The returned configuration includes:
     * - JWT settings
     * - Passport strategy configuration
     * - Authentication module options
     * 
     * @returns {Promise<IAuth.IConfiguration.IAuthentication> | IAuth.IConfiguration.IAuthentication}
     * Authentication configuration object
     */
    createAuthenticationOptions(): Promise<IAuth.IConfiguration.IAuthentication> | IAuth.IConfiguration.IAuthentication;
}

/**
 * Configuration interface for asynchronous authentication module setup.
 * 
 * @interface AuthenticationModuleAsyncOptions
 * @description
 * Provides comprehensive configuration options for setting up authentication
 * asynchronously. This interface supports multiple configuration patterns:
 * - Factory functions
 * - Existing providers
 * - Class-based factories
 * 
 * It enables dependency injection and modular configuration of authentication
 * features including Web2/Web3 authentication, admin access, and 2FA.
 * 
 * @example
 * ```typescript
 * const asyncConfig: AuthenticationModuleAsyncOptions = {
 *   imports: [ConfigModule],
 *   useFactory: async (configService: ConfigService) => ({
 *     commonOptions: {
 *       jwt: { secret: configService.get('JWT_SECRET') },
 *       passport: 'jwt'
 *     },
 *     config: {
 *       module: 'web2',
 *       options: {
 *         enable_2fa: true,
 *         admin_only: false
 *       }
 *     }
 *   }),
 *   inject: [ConfigService]
 * };
 * ```
 */
export interface AuthenticationModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
    /**
     * Existing AuthenticationOptionsFactory to use.
     * 
     * @description
     * References an existing factory implementation for creating authentication options.
     * Useful when reusing existing authentication configuration logic.
     * 
     * @type {Array<Type<any>>}
     */
    useExisting?: Array<Type<any>>;

    /**
     * Class to instantiate as AuthenticationOptionsFactory.
     * 
     * @description
     * Specifies a class that implements AuthenticationOptionsFactory interface.
     * The class will be instantiated to create the authentication configuration.
     * 
     * @type {Type<any>}
     */
    useClass?: Type<any>;

    /**
     * Factory function for creating authentication options.
     * 
     * @description
     * Function that generates authentication configuration dynamically.
     * Supports dependency injection through the inject array.
     * 
     * @param {...any[]} args - Dependencies injected from the inject array
     * @returns {Promise<IAuth.IConfiguration.IAuthentication> | IAuth.IConfiguration.IAuthentication}
     */
    useFactory?: (...args: any[]) => Promise<IAuth.IConfiguration.IAuthentication> | IAuth.IConfiguration.IAuthentication;

    /**
     * Dependencies to inject into the factory function.
     * 
     * @description
     * Array of providers to be injected into the factory function.
     * These dependencies are available as parameters to the factory function.
     * 
     * @type {any[]}
     */
    inject?: any[];

    /**
     * Core authentication configuration settings.
     * 
     * @description
     * Defines the fundamental authentication setup including:
     * - Passport strategy selection (JWT/Redis)
     * - Authentication module type (Web2/Web3)
     * - Security and access control options
     * 
     * @property {IAuth.IConfiguration.IPassportStrategy} passport - Passport authentication strategy
     * @property {'web2' | 'web3'} module - Authentication module type
     * @property {Object} options - Authentication feature flags and settings
     */
    config: {
        passport: IAuth.IConfiguration.IPassportStrategy,
        module: 'web2' | 'web3',
        options: {
            /** Whether email confirmation is required for account activation */
            confirmation_required: boolean,
            /** Whether access is restricted to administrators only */
            admin_only: boolean,
            /** Whether two-factor authentication is enabled */
            enable_2fa: boolean
        }
    }
}