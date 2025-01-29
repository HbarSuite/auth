import { Module } from '@nestjs/common'
import * as Redis from 'redis'

import { AUTHREDIS } from './redis.constants'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { IAuth } from '@hsuite/auth-types'
import { CookieOptions } from 'express'
import { Config } from 'cache-manager'

/**
 * Redis Authentication Module
 * 
 * @description
 * This module provides Redis-based session management and authentication functionality.
 * It handles:
 * - Redis client configuration and connection management
 * - Session storage configuration
 * - Cookie settings for session management
 * 
 * The module is conditionally configured based on the selected authentication strategy
 * (Redis vs JWT) and provides necessary providers for Redis-based authentication.
 * 
 * @module
 * @example
 * ```typescript
 * // Import and use in AppModule
 * @Module({
 *   imports: [
 *     RedisAuthModule,
 *     ConfigModule.forRoot({
 *       load: [
 *         () => ({
 *           authentication: {
 *             commonOptions: {
 *               passport: 'redis',
 *               redis: {
 *                 socket: { host: 'localhost', port: 6379 }
 *               }
 *             }
 *           }
 *         })
 *       ]
 *     })
 *   ]
 * })
 * export class AppModule {}
 * ```
 */
@Module({
  imports: [
    ConfigModule
  ],
  providers: [
    {
      provide: AUTHREDIS,
      /**
       * Factory function for Redis client configuration.
       * 
       * @description
       * This factory function:
       * 1. Checks if Redis authentication strategy is enabled
       * 2. Creates and configures Redis client if enabled
       * 3. Sets up session cookie options and application name
       * 
       * The configuration includes:
       * - Redis connection settings (host, port, credentials)
       * - Cookie configuration for sessions
       * - Application name for session identification
       * 
       * @param {ConfigService} config - NestJS configuration service
       * @returns {Promise<{
       *   client: Redis.RedisClientType,
       *   cookieOptions: CookieOptions,
       *   appName: string
       * } | null>} Redis configuration object or null if not using Redis
       * 
       * @throws {Error} If Redis connection fails
       */
      useFactory: async (config: ConfigService) => {
        let passport: IAuth.IConfiguration.IPassportStrategy = config.get<IAuth.IConfiguration.IPassportStrategy>('authentication.commonOptions.passport');
        
        if(passport == IAuth.IConfiguration.IPassportStrategy.REDIS) {
          let redis: any = config.get<Redis.RedisClientOptions & Config>('authentication.commonOptions.redis');
          let cookieOptions: CookieOptions = config.get<any>('authentication.commonOptions.cookieOptions');
          let appName: string = config.get<any>('authentication.commonOptions.appName');

          const client = Redis.createClient({
            username: redis.username,
            password: redis.password,
            database: redis.database,
            socket: {
              host: redis.socket.host,
              port: redis.socket.port
            },
            legacyMode: false
          });
  
          await client.connect();

          return {
            client: client,
            cookieOptions: cookieOptions,
            appName: appName
          };
        } else {
          return null;
        }
      },
      inject: [ConfigService]
    },
  ],
  exports: [AUTHREDIS]
})
export class RedisAuthModule {}