import { DynamicModule, Global, Inject, MiddlewareConsumer, Module } from '@nestjs/common'
import { AuthService } from './auth.service'
import { IAuthModuleOptions, PassportModule } from '@nestjs/passport'
import { JwtModule, JwtModuleOptions, JwtService } from '@nestjs/jwt'
import { JwtStrategy } from './strategies/jwt.strategy'
import { SessionSerializer } from './serializers/session.serializer'
import { RedisAuthModule } from './redis/redis.module'
import { AUTHREDIS } from './redis/redis.constants'
import { createClient } from 'redis'
import * as session from 'express-session'
import * as passport from 'passport'
import { AuthWeb2Module } from './web2/src'
import { AuthWeb3Module } from './web3/src'
import { APP_GUARD } from '@nestjs/core'
import { RedisAuthGuard } from './guards/redis.guard'
import { JwtAuthGuard } from './guards/jwt.guard'
import { IHashgraph } from "@hsuite/hashgraph-types";
import { IAuth } from '@hsuite/auth-types'
import { AuthController } from './auth.controller'
import { ConfirmedAuthGuard } from './guards/confirmed.guard'
import { UsersModule } from '@hsuite/users'
import { AuthenticationModuleAsyncOptions } from './interfaces/auth-options.interface'
import { ISendMailOptions, MailerOptions } from '@nestjs-modules/mailer'

/**
 * Interface defining Redis authentication configuration options.
 * 
 * @interface IAuthRedis
 * @description
 * This interface specifies the required configuration for Redis-based authentication:
 * - Redis client instance for session storage
 * - Cookie configuration for session management
 * - Application name for session identification
 * 
 * @property {typeof createClient} client - Redis client instance for session storage
 * @property {any} cookieOptions - Cookie configuration options for session
 * @property {string} appName - Application name for session identification
 */
interface IAuthRedis {
  client: typeof createClient
  cookieOptions: any
  appName: string
}

/**
 * Global authentication module providing centralized auth functionality.
 * 
 * @description
 * This module handles all authentication-related features including:
 * - JWT and Redis-based authentication strategies
 * - Web2 (username/password) and Web3 (wallet) authentication
 * - Session management and serialization
 * - Guards for route protection
 * 
 * The module can be configured asynchronously to support dynamic configuration loading.
 * It supports both JWT and Redis-based session management strategies.
 * 
 * @example
 * ```typescript
 * // Register auth module asynchronously with config service
 * AuthModule.forRootAsync({
 *   imports: [ConfigModule],
 *   useFactory: async (config: ConfigService) => ({
 *     commonOptions: {
 *       jwt: { secret: config.get('JWT_SECRET') },
 *       passport: 'jwt',
 *       operator: { ... }
 *     }
 *   }),
 *   inject: [ConfigService]
 * });
 * ```
 */
@Global()
@Module({
  imports: [
    RedisAuthModule
  ]
})
export class AuthModule {
  /**
   * Creates an instance of AuthModule.
   * 
   * @constructor
   * @param {IAuthRedis} redis - Redis client and configuration options for session management
   */
  constructor(
    @Inject(AUTHREDIS) private readonly redis: IAuthRedis
  ) {}

  /**
   * Asynchronously configures and returns the AuthModule.
   * 
   * @static
   * @async
   * @description
   * This method configures the authentication module with:
   * - Passport authentication strategies
   * - JWT module configuration
   * - Web2 or Web3 authentication based on config
   * - Required providers and guards
   * 
   * The configuration supports both JWT and Redis-based authentication strategies,
   * with optional features like 2FA and admin-only access.
   * 
   * @param {AuthenticationModuleAsyncOptions} options - Async configuration options
   * @returns {Promise<DynamicModule>} Configured DynamicModule instance
   */
  static async forRootAsync(options: AuthenticationModuleAsyncOptions): Promise<DynamicModule> {    
    return {
      module: AuthModule,
      imports: [
        UsersModule,
        PassportModule.register({
          ...options,
          useFactory: async (...args) => (
            <IAuthModuleOptions> {
              defaultStrategy: (await options.useFactory?.(...args)).commonOptions.passport,
              session: true
            }
          )
        }),
        JwtModule.registerAsync({
          inject: options.inject,
          useFactory: async (...args) => ({
            ...<JwtModuleOptions> (await options.useFactory?.(...args)).commonOptions.jwt
          })
        }),
        ...(
          options.config.module == 'web2' ?
            [AuthWeb2Module.forRootAsync({
              ...options,
              useFactory: async (...args) => {
                const factory = await options.useFactory?.(...args);
                return {
                  jwt: <JwtModuleOptions> factory.commonOptions.jwt,
                  operator: <IHashgraph.IOperator> factory.commonOptions.operator,
                  confirmation_required: <boolean> factory.web2Options.confirmation_required,
                  admin_only: <boolean> factory.web2Options.admin_only,
                  passport: <IAuth.IConfiguration.IPassportStrategy> factory.commonOptions.passport,
                  sendMailOptions: <{confirm: ISendMailOptions, reset: ISendMailOptions}> factory.web2Options.sendMailOptions,
                  mailerOptions: <MailerOptions> factory.web2Options.mailerOptions,
                  twilioOptions: <IAuth.ITwilio.IOptions> factory.web2Options.twilioOptions
                }
              },
              config: {
                admin_only: <boolean> options.config.options.admin_only,
                enable_2fa: <boolean> options.config.options.enable_2fa
              }       
            })] :
            [AuthWeb3Module.forRootAsync({
              ...options,
              useFactory: async (...args) => {
                const factory = await options.useFactory?.(...args);
                return {
                  jwt: <JwtModuleOptions> factory.commonOptions.jwt,
                  operator: <IHashgraph.IOperator> factory.commonOptions.operator,
                  passport: <IAuth.IConfiguration.IPassportStrategy> factory.commonOptions.passport,
                  tokenGateOptions: <IAuth.IConfiguration.IWeb3.ITokenGate.IOptions> factory.web3Options.tokenGateOptions
                }
              }
            })]
        )
      ],
      controllers: [
        AuthController
      ],
      providers: [
        {
          provide: 'authOptions',
          useFactory: options.useFactory,
          inject: options.useExisting
        },
        AuthService,
        JwtStrategy,
        SessionSerializer,
        {
          provide: 'JwtAuthService',
          useExisting: JwtService,
        },
        ...(
          options.config.passport == IAuth.IConfiguration.IPassportStrategy.REDIS ?
            [{
              provide: APP_GUARD,
              useClass: RedisAuthGuard,
            }] :
            [{
              provide: APP_GUARD,
              useClass: JwtAuthGuard,
            }]
        ),
        ...(
          options.config.module == 'web2' && options.config.options.confirmation_required ?
            [{
              provide: APP_GUARD,
              useClass: ConfirmedAuthGuard,
            }] : []
        )
      ],
      exports: [
        AuthService,
        JwtStrategy,
        SessionSerializer,
        'JwtAuthService'
      ]
    }    
  }

  /**
   * Configures session middleware for Redis-based authentication.
   * 
   * @description
   * This method sets up:
   * - Redis session store configuration
   * - Session middleware with cookie options
   * - Passport initialization and session handling
   * 
   * The middleware is only configured if a Redis client is provided.
   * It applies session management to all routes ('*').
   * 
   * @param {MiddlewareConsumer} consumer - MiddlewareConsumer to apply session middleware
   */
  configure(consumer: MiddlewareConsumer) {
    if (this.redis != null) {
      const RedisStore = require("connect-redis").default;
      let store = new RedisStore({ client: <any>this.redis.client, logErrors: true });
      consumer
        .apply(
          session({
            store: store,
            secret: process.env.SESSION_SECRET,
            resave: false,
            saveUninitialized: true,
            proxy: true,
            name: this.redis.appName,
            cookie: this.redis.cookieOptions,
          }),
          passport.initialize(),
          passport.session(),
        )
        .forRoutes('*');
    }
  }
}
