import { DynamicModule, Module } from '@nestjs/common'
import { AuthWeb2Service } from './web2.service'
import { UsersModule } from '@hsuite/users'
import { Web2Strategy } from '../strategies/web2.strategy'
import { AuthWeb2SessionController } from './web2.sessions.controller'
import { AuthWeb2AccountsController } from './web2.accounts.controller'
import { MailerModule } from '@nestjs-modules/mailer'
import { TwoFactoryAuthModule } from '../../2fa/2fa.module'
import { APP_GUARD } from '@nestjs/core'
import { TwoFactoryAuthGuard } from '../../2fa/auth/auth.guard'
import { AdminAuthGuard } from '../guards/admin.guard'
import { Web2ModuleAsyncOptions } from '../interfaces/web2-options.interface'

/**
 * Web2 Authentication Module
 * 
 * @description
 * This module provides comprehensive Web2 authentication functionality including:
 * - Email/password based authentication flows
 * - Two-factor authentication (2FA) support
 * - Admin-only access restrictions
 * - Email services integration
 * - Session management and persistence
 * - Account management capabilities
 * 
 * The module is designed to be configured asynchronously to allow for:
 * - Dynamic configuration of authentication options
 * - Flexible 2FA enablement/configuration
 * - Admin-only mode toggling
 * - Custom mailer and notification settings
 * - Integration with Twilio for 2FA services
 * 
 * @module
 * @example
 * ```typescript
 * // Basic module configuration
 * AuthWeb2Module.forRootAsync({
 *   config: {
 *     enable_2fa: true,
 *     admin_only: false
 *   },
 *   useFactory: async (config: ConfigService) => ({
 *     mailerOptions: {
 *       transport: {
 *         host: config.get('MAIL_HOST'),
 *         port: config.get('MAIL_PORT')
 *       }
 *     },
 *     twilioOptions: {
 *       accountSid: config.get('TWILIO_SID'),
 *       authToken: config.get('TWILIO_TOKEN')
 *     }
 *   })
 * })
 * ```
 */
@Module({})
export class AuthWeb2Module {
  /**
   * Asynchronously configures and creates a dynamic Web2 Authentication module
   * 
   * @param {Web2ModuleAsyncOptions} options - Configuration options for the module
   * @returns {Promise<DynamicModule>} A promise resolving to the configured dynamic module
   * 
   * @description
   * This method configures the Web2 Authentication module with the following capabilities:
   * 
   * Core Features:
   * - Integration with Users module for account management
   * - Email service configuration through MailerModule
   * - Optional Two-Factor Authentication (2FA)
   * - Admin-only mode restrictions
   * 
   * Module Components:
   * - Controllers for session and account management
   * - Authentication services and strategies
   * - Security guards for 2FA and admin access
   * 
   * Configuration Options:
   * - Mailer settings for email notifications
   * - Twilio integration for 2FA
   * - Access control settings
   * - Guard configurations
   * 
   * @example
   * ```typescript
   * // Advanced configuration with all options
   * AuthWeb2Module.forRootAsync({
   *   imports: [ConfigModule],
   *   inject: [ConfigService],
   *   config: {
   *     enable_2fa: true,
   *     admin_only: true
   *   },
   *   useFactory: async (configService: ConfigService) => ({
   *     mailerOptions: {
   *       transport: {
   *         host: configService.get('MAIL_HOST'),
   *         port: configService.get('MAIL_PORT'),
   *         secure: true,
   *         auth: {
   *           user: configService.get('MAIL_USER'),
   *           pass: configService.get('MAIL_PASS')
   *         }
   *       },
   *       defaults: {
   *         from: '"No Reply" <noreply@example.com>'
   *       }
   *     },
   *     twilioOptions: {
   *       accountSid: configService.get('TWILIO_SID'),
   *       authToken: configService.get('TWILIO_TOKEN'),
   *       verificationServiceSid: configService.get('TWILIO_VERIFY_SID')
   *     }
   *   })
   * })
   * ```
   */
  static async forRootAsync(options: Web2ModuleAsyncOptions): Promise<DynamicModule> {
    return {
      module: AuthWeb2Module,
      // Import required modules - Users, Mailer, and optionally 2FA
      imports: [
        UsersModule,
        MailerModule.forRootAsync({
          inject: options.inject,
          useFactory: async (...args) => {
            const factory = await options.useFactory?.(...args);
            return {
              transport: factory.mailerOptions.transport,
              defaults: factory.mailerOptions.defaults
            }
          }
        }),
        // Conditionally import 2FA module if enabled
        ...(
          options.config.enable_2fa ?
            [
              TwoFactoryAuthModule.forRootAsync({
                ...options,
                useFactory: async (...args) => {
                  const factory = await options.useFactory?.(...args);
                  return factory.twilioOptions;
                }
              })
            ] : []
        )
      ],
      // Configure controllers based on admin-only setting
      controllers: [
        ...(
          options.config.admin_only ?
            [
              AuthWeb2SessionController
            ] : [
              AuthWeb2SessionController,
              AuthWeb2AccountsController
            ]
        ),
      ],
      // Set up providers including guards and services
      providers: [
        {
          provide: 'authWeb2Options',
          useFactory: options.useFactory
        },
        // Add 2FA guard if enabled
        ...(
          options.config.enable_2fa ?
            [
              {
                provide: APP_GUARD,
                useClass: TwoFactoryAuthGuard,
              }
            ] : []
        ),
        // Add admin guard if in admin-only mode
        ...(
          options.config.admin_only ?
            [
              {
                provide: APP_GUARD,
                useClass: AdminAuthGuard,
              }
            ] : []
        ),
        AuthWeb2Service,
        Web2Strategy
      ],
      // Export service and strategy for use in other modules
      exports: [
        AuthWeb2Service,
        Web2Strategy
      ]
    }
  }    
}
