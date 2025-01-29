/**
 * Two-Factor Authentication (2FA) Module
 * 
 * @module TwoFactorAuth
 * @description
 * This module provides comprehensive Two-Factor Authentication functionality
 * using Twilio's Verify API for secure TOTP-based authentication.
 * 
 * Core Features:
 * - TOTP-based two-factor authentication
 * - QR code generation for authenticator apps
 * - SMS-based verification codes
 * - Factor management (create, verify, delete)
 * - Challenge creation and validation
 * 
 * Components:
 * - TwoFactoryAuthModule: Core module configuration
 * - TwoFactoryAuthService: Twilio integration and business logic
 * - TwoFactoryAuthController: HTTP endpoints for 2FA operations
 * - TwoFactorAuthGuard: Route protection requiring 2FA
 * 
 * Integration:
 * - Twilio Verify API for secure factor management
 * - Authenticator apps (Google Authenticator, Authy, etc.)
 * - SMS delivery for verification codes
 * - User service for persistence
 * 
 * @example
 * ```typescript
 * // Import and configure 2FA module
 * import { TwoFactoryAuthModule } from '@hsuite/auth/2fa';
 * 
 * @Module({
 *   imports: [
 *     TwoFactoryAuthModule.forRootAsync({
 *       imports: [ConfigModule],
 *       useFactory: async (config: ConfigService) => ({
 *         twilioSecrets: {
 *           accountSid: config.get('TWILIO_ACCOUNT_SID'),
 *           authToken: config.get('TWILIO_AUTH_TOKEN'),
 *           serviceSid: config.get('TWILIO_SERVICE_SID')
 *         },
 *         enabled: true
 *       }),
 *       inject: [ConfigService]
 *     })
 *   ]
 * })
 * export class AppModule {}
 * 
 * // Protect routes with 2FA
 * @UseGuards(TwoFactorAuthGuard)
 * @TwoFactorAuth()
 * @Get('protected')
 * getProtectedData() {
 *   return 'This endpoint requires 2FA';
 * }
 * ```
 */

// Export main 2FA module for configuration
export * from './2fa.module'

// Export service containing 2FA business logic
export * from './2fa.service'

// Export controller with 2FA endpoints
export * from './2fa.controller'

// Export guard for 2FA route protection
export * from './auth/auth.guard'