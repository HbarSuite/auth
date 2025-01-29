/**
 * Web3 Authentication Module
 * 
 * @module Web3Auth
 * @description
 * This module provides Web3 wallet-based authentication functionality.
 * 
 * Core Features:
 * - Wallet-based authentication
 * - Token-gated access control
 * - NFT ownership verification
 * - Multi-chain support
 * - Signature verification
 * 
 * Components:
 * - AuthWeb3Module: Core Web3 authentication configuration
 * - AuthWeb3Service: Web3 authentication business logic
 * - Web3Controller: Authentication endpoints
 * - Web3Guard: Route protection
 * - Web3Strategy: Passport strategy for wallet auth
 * 
 * Additional Features:
 * - Support for multiple blockchain networks
 * - NFT-based role assignment
 * - Token balance verification
 * - IPFS metadata integration
 * - Cross-chain authentication
 * 
 * @example
 * ```typescript
 * // Import and use Web3 authentication
 * import { AuthWeb3Module } from '@hsuite/auth/web3';
 * 
 * @Module({
 *   imports: [
 *     AuthWeb3Module.forRootAsync({
 *       imports: [ConfigModule],
 *       useFactory: async (config: ConfigService) => ({
 *         jwt: { secret: config.get('JWT_SECRET') },
 *         tokenGateOptions: {
 *           enabled: true,
 *           networks: ['ethereum', 'polygon'],
 *           roles: [
 *             {
 *               tokenId: '0x...',
 *               role: 'premium'
 *             }
 *           ]
 *         }
 *       })
 *     })
 *   ]
 * })
 * export class AppModule {}
 * ```
 */

// Export Web3 authentication module for configuration
export * from './auth/web3.module'

// Export service handling Web3 auth operations
export * from './auth/web3.service'

// Export controller with auth endpoints
export * from './auth/web3.controller'

// Export guard for protecting routes
export * from './guards/web3.guard'

// Export Passport strategy implementation
export * from './strategies/web3.strategy'
