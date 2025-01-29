import { DynamicModule, Module } from '@nestjs/common'
import { AuthWeb3Service } from './web3.service'
import { Web3Strategy } from '../strategies/web3.strategy'
import { AuthWeb3Controller } from './web3.controller'
import { Web3ModuleAsyncOptions } from '../interfaces/web3-options.interface'
import { IpfsModule } from '@hsuite/ipfs'

/**
 * Module for handling Web3 authentication functionality.
 * 
 * @description
 * This module provides Web3 wallet-based authentication capabilities including:
 * - Web3 authentication service for handling core logic
 * - Web3 strategy for Passport integration
 * - Controller for exposing authentication endpoints
 * - HTTP module for external Web3 provider communication
 * - IPFS integration for decentralized storage
 * 
 * The module supports:
 * - Wallet signature verification
 * - Nonce generation and validation
 * - Session management
 * - Integration with IPFS for metadata storage
 * 
 * @example
 * ```typescript
 * // Register the module asynchronously
 * @Module({
 *   imports: [
 *     AuthWeb3Module.forRootAsync({
 *       imports: [ConfigModule],
 *       useFactory: async (configService: ConfigService) => ({
 *         passport: configService.get('AUTH_STRATEGY'),
 *         web3Provider: configService.get('WEB3_PROVIDER'),
 *         ipfsGateway: configService.get('IPFS_GATEWAY')
 *       }),
 *       inject: [ConfigService]
 *     })
 *   ]
 * })
 * ```
 * 
 * @publicApi
 */
@Module({})
export class AuthWeb3Module {
  /**
   * Asynchronously configures and returns the AuthWeb3Module.
   * 
   * @description
   * This method allows for dynamic configuration of the module using
   * async factory functions and dependency injection.
   * 
   * The configuration includes:
   * - Setting up required imports including IPFS module
   * - Registering the auth controller
   * - Configuring providers with injected options
   * - Exporting core services and strategies
   * 
   * The method supports:
   * - Custom imports through options.imports
   * - Factory-based configuration via options.useFactory
   * - Dependency injection through options.inject
   * - Dynamic provider configuration
   * - Module exports for external usage
   * 
   * @param options - Configuration options for the module
   * @param options.imports - Array of modules to import
   * @param options.useFactory - Factory function for creating config
   * @param options.inject - Array of dependencies to inject
   * @returns {Promise<DynamicModule>} A promise that resolves to a configured DynamicModule instance
   * 
   * @throws {Error} When required options are missing
   * @throws {Error} When factory function fails
   * 
   * @example
   * ```typescript
   * AuthWeb3Module.forRootAsync({
   *   imports: [ConfigModule],
   *   useFactory: async (config: ConfigService) => ({
   *     web3Provider: config.get('WEB3_PROVIDER'),
   *     ipfsGateway: config.get('IPFS_GATEWAY')
   *   }),
   *   inject: [ConfigService]
   * });
   * ```
   */
  static async forRootAsync(options: Web3ModuleAsyncOptions): Promise<DynamicModule> {
    return {
      module: AuthWeb3Module,
      imports: [
        ...options.imports, // Import any additional modules specified in options
        IpfsModule
      ],
      controllers: [
        AuthWeb3Controller // Register the Web3 auth controller
      ],
      providers: [
        {
          provide: 'authWeb3Options', // Provide configuration options
          useFactory: options.useFactory,
          inject: options.inject
        },
        AuthWeb3Service, // Core Web3 authentication service
        Web3Strategy // Passport strategy for Web3 auth
      ],
      exports: [
        AuthWeb3Service, // Export service for use in other modules
        Web3Strategy // Export strategy for use in other modules
      ]
    }
  }  
}
