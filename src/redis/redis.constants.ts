/**
 * Symbol used for Redis authentication injection token
 * 
 * @constant
 * @description This symbol is used as a unique identifier for dependency injection
 * of Redis-related authentication services and configurations. It helps maintain
 * clear separation between different authentication mechanisms in the application.
 * 
 * @example
 * ```typescript
 * @Inject(AUTHREDIS)
 * private redisAuthService: RedisAuthService
 * ```
 */
export const AUTHREDIS = Symbol('AUTH:REDIS');