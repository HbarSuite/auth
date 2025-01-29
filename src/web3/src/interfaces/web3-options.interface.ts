import { IAuth } from '@hsuite/auth-types'
import { ModuleMetadata, Type } from '@nestjs/common/interfaces';

/**
 * Interface defining the factory for creating Web3 authentication options.
 * 
 * @description
 * This interface provides a contract for factories that create Web3 authentication
 * configuration options. It ensures consistent option generation across the module.
 * 
 * @example
 * ```typescript
 * class CustomWeb3OptionsFactory implements Web3OptionsFactory {
 *   async createWeb3Options() {
 *     return {
 *       passport: 'jwt',
 *       web3Provider: 'https://provider.example.com'
 *     };
 *   }
 * }
 * ```
 */
export interface Web3OptionsFactory {
    /**
     * Creates and returns the Web3 authentication options.
     * 
     * @description
     * This method generates the configuration options needed for Web3 authentication.
     * It can return options synchronously or as a Promise.
     * 
     * @returns A promise that resolves to auth options or the options directly.
     * The options combine Web3-specific settings with general auth configuration.
     */
    createWeb3Options(): Promise<Partial<IAuth.IConfiguration.IWeb3.IOptions> & Partial<IAuth.IConfiguration.IOptions>> | 
        Partial<IAuth.IConfiguration.IWeb3.IOptions> & Partial<IAuth.IConfiguration.IOptions>;
}

/**
 * Interface for asynchronous Web3 authentication module configuration.
 * 
 * @description
 * This interface defines the structure for configuring the Web3 authentication module
 * asynchronously. It extends ModuleMetadata to include import capabilities and provides
 * multiple ways to configure the module:
 * - Using an existing factory
 * - Using a new factory class
 * - Using a factory function
 * 
 * @example
 * ```typescript
 * AuthWeb3Module.forRootAsync({
 *   imports: [ConfigModule],
 *   useFactory: async (config: ConfigService) => ({
 *     passport: config.get('AUTH_STRATEGY'),
 *     web3Provider: config.get('WEB3_PROVIDER')
 *   }),
 *   inject: [ConfigService]
 * });
 * ```
 */
export interface Web3ModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
    /**
     * An existing Web3OptionsFactory type to be used for configuration.
     * Allows reusing an existing factory implementation.
     */
    useExisting?: Array<Type<any>>;

    /**
     * A class to be instantiated as a Web3OptionsFactory.
     * Enables providing a new factory implementation.
     */
    useClass?: Type<any>;

    /**
     * A factory function that returns Web3 authentication options.
     * 
     * @description
     * This function can be used to dynamically generate configuration options.
     * It supports dependency injection through the inject property.
     * 
     * @param args - Dependencies injected into the factory function
     * @returns Promise or direct value containing Web3 auth configuration
     */
    useFactory?: (...args: any[]) => Promise<Partial<IAuth.IConfiguration.IWeb3.IOptions> & Partial<IAuth.IConfiguration.IOptions>> | 
        Partial<IAuth.IConfiguration.IWeb3.IOptions> & Partial<IAuth.IConfiguration.IOptions>;

    /**
     * Optional list of providers to be injected into the factory function.
     * These providers must be available in the module context.
     */
    inject?: any[];
}