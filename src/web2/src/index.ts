/**
 * Web2 Authentication Module
 * 
 * @module Web2Auth
 * @description
 * This module provides traditional username/password (Web2) authentication functionality.
 * 
 * Core Features:
 * - User registration and login with email/password
 * - Password management (reset, recovery)
 * - Email verification and confirmation
 * - Session management and persistence
 * - Two-factor authentication (2FA)
 * 
 * Components:
 * - AuthWeb2Module: Core authentication module configuration
 * - AuthWeb2Service: Authentication business logic
 * - Web2SessionsController: Session management endpoints
 * - Web2AccountsController: Account management endpoints
 * - Web2Guard: Route protection
 * - Web2Strategy: Passport authentication strategy
 * 
 * Additional Features:
 * - Email templates for verification and password reset
 * - SMS-based 2FA via Twilio integration
 * - Admin-only access mode
 * - Configurable email confirmation requirement
 * 
 * @example
 * ```typescript
 * // Import and use Web2 authentication
 * import { AuthWeb2Module } from '@hsuite/auth/web2';
 * 
 * @Module({
 *   imports: [
 *     AuthWeb2Module.forRootAsync({
 *       imports: [ConfigModule],
 *       useFactory: async (config: ConfigService) => ({
 *         jwt: { secret: config.get('JWT_SECRET') },
 *         confirmation_required: true,
 *         admin_only: false,
 *         enable_2fa: true
 *       })
 *     })
 *   ]
 * })
 * export class AppModule {}
 * ```
 */

// Export core Web2 authentication module and service
export * from './auth/web2.module'
export * from './auth/web2.service'

// Export controllers for session and account management
export * from './auth/web2.sessions.controller'
export * from './auth/web2.accounts.controller'

// Export authentication guard and strategy
export * from './guards/web2.guard'
export * from './strategies/web2.strategy'

// Export 2FA functionality
export * from '../2fa/index'