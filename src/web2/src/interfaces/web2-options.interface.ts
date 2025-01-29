import { IAuth } from '@hsuite/auth-types'
import { ModuleMetadata, Type } from '@nestjs/common/interfaces';

/**
 * Interface defining the factory for creating Web2 authentication options.
 * 
 * @description
 * This factory interface provides a contract for creating Web2 authentication options
 * that can be used to configure the authentication module. It allows for both
 * synchronous and asynchronous creation of options.
 * 
 * @publicApi
 * @interface
 * 
 * @example
 * ```typescript
 * class CustomWeb2OptionsFactory implements Web2OptionsFactory {
 *   async createWeb2Options() {
 *     return {
 *       passport: 'jwt',
 *       secret: 'my-secret'
 *     };
 *   }
 * }
 * ```
 */
export interface Web2OptionsFactory {
    /**
     * Creates and returns the Web2 authentication options.
     * 
     * @description
     * This method is responsible for generating the configuration options
     * needed by the Web2 authentication module. It can return options either
     * synchronously or as a Promise.
     * 
     * @returns {Promise<Partial<IAuth.IConfiguration.IWeb2.IOptions> & Partial<IAuth.IConfiguration.IOptions>> | Partial<IAuth.IConfiguration.IWeb2.IOptions> & Partial<IAuth.IConfiguration.IOptions>} A promise that resolves to auth options or the options directly.
     * 
     * @public
     */
    createWeb2Options(): Promise<Partial<IAuth.IConfiguration.IWeb2.IOptions> & Partial<IAuth.IConfiguration.IOptions>> | 
        Partial<IAuth.IConfiguration.IWeb2.IOptions> & Partial<IAuth.IConfiguration.IOptions>;
}

/**
 * Interface for asynchronous Web2 authentication module configuration.
 * 
 * @description
 * This interface defines the structure for configuring the Web2 authentication module
 * asynchronously. It supports different patterns for providing options:
 * - Using an existing factory
 * - Creating a new factory class
 * - Using a factory function
 * 
 * @publicApi
 * @interface
 * @extends {Pick<ModuleMetadata, 'imports'>}
 * 
 * @example
 * ```typescript
 * const asyncConfig: Web2ModuleAsyncOptions = {
 *   imports: [ConfigModule],
 *   useFactory: async (configService: ConfigService) => ({
 *     passport: configService.get('AUTH_STRATEGY'),
 *     secret: configService.get('JWT_SECRET')
 *   }),
 *   inject: [ConfigService],
 *   config: {
 *     admin_only: true,
 *     enable_2fa: false
 *   }
 * };
 * ```
 */
export interface Web2ModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
    /**
     * An existing Web2OptionsFactory type to be used.
     * 
     * @description
     * Allows reusing an existing factory implementation.
     * 
     * @type {Array<Type<any>>}
     */
    useExisting?: Array<Type<any>>;

    /**
     * A class to be instantiated as a Web2OptionsFactory.
     * 
     * @description
     * Enables providing a custom factory class implementation.
     * 
     * @type {Type<any>}
     */
    useClass?: Type<any>;

    /**
     * A factory function that returns Web2 authentication options.
     * 
     * @description
     * This function can be used to dynamically generate options based on
     * injected dependencies or other runtime factors.
     * 
     * @param {...any[]} args - Any arguments that the factory might need.
     * @returns {Promise<Partial<IAuth.IConfiguration.IWeb2.IOptions> & Partial<IAuth.IConfiguration.IOptions>> | Partial<IAuth.IConfiguration.IWeb2.IOptions> & Partial<IAuth.IConfiguration.IOptions>} A promise that resolves to auth options or the options directly.
     */
    useFactory?: (...args: any[]) => Promise<Partial<IAuth.IConfiguration.IWeb2.IOptions> & Partial<IAuth.IConfiguration.IOptions>> | 
        Partial<IAuth.IConfiguration.IWeb2.IOptions> & Partial<IAuth.IConfiguration.IOptions>;

    /**
     * Optional list of providers to be injected into the context of the Factory function.
     * 
     * @description
     * These providers will be available as parameters to the factory function.
     * 
     * @type {any[]}
     */
    inject?: any[];

    /**
     * Configuration options for the Web2 authentication module.
     * 
     * @description
     * Core configuration settings that determine the behavior of the
     * Web2 authentication module.
     * 
     * @type {{admin_only: boolean, enable_2fa: boolean}}
     */
    config: {
        /**
         * Indicates whether the module should be restricted to admin users only.
         * 
         * @description
         * When true, only users with admin privileges can access protected routes.
         * 
         * @type {boolean}
         */
        admin_only: boolean;

        /**
         * Indicates whether two-factor authentication should be enabled.
         * 
         * @description
         * When true, users will be required to provide a second form of authentication.
         * 
         * @type {boolean}
         */
        enable_2fa: boolean;
    }
}