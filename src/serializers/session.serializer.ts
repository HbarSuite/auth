import { Injectable } from "@nestjs/common"
import { PassportSerializer } from "@nestjs/passport"

/**
 * Session Serializer for Redis-based Authentication.
 * 
 * @description
 * This serializer handles the conversion of user objects for session storage.
 * It provides:
 * - User object serialization for session storage
 * - User data deserialization from sessions
 * - Customizable serialization logic
 * 
 * The serializer is essential for Redis-based session management,
 * ensuring proper user data handling between requests.
 * 
 * @class
 * @extends {PassportSerializer}
 * 
 * @example
 * ```typescript
 * // Register serializer in module
 * @Module({
 *   providers: [SessionSerializer],
 *   exports: [SessionSerializer]
 * })
 * export class AuthModule {}
 * 
 * // Use in authentication flow
 * const user = await authService.validateUser(credentials);
 * // Serializer automatically handles session storage
 * ```
 */
@Injectable()
export class SessionSerializer extends PassportSerializer {
  /**
   * Serializes user data for session storage.
   * 
   * @param {any} user - User object to serialize
   * @param {Function} done - Callback for serialization completion
   * 
   * @description
   * This method handles the conversion of user objects for storage:
   * 1. Receives the authenticated user object
   * 2. Processes it for session storage (if needed)
   * 3. Passes the serialized data to the callback
   * 
   * The current implementation passes the user object as-is,
   * but can be customized for specific serialization needs.
   * 
   * @example
   * ```typescript
   * // Custom serialization example
   * serializeUser(user, done) {
   *   // Store only necessary user data
   *   const sessionData = {
   *     id: user._id,
   *     email: user.email
   *   };
   *   done(null, sessionData);
   * }
   * ```
   */
  serializeUser(user: any, done: (err: Error | null, user: any) => void): void {
    done(null, user)
  }
  
  /**
   * Deserializes user data from session storage.
   * 
   * @param {any} payload - Serialized user data from session
   * @param {Function} done - Callback for deserialization completion
   * 
   * @description
   * This method handles the restoration of user data from sessions:
   * 1. Receives the serialized session data
   * 2. Processes it back into a user object (if needed)
   * 3. Passes the deserialized user to the callback
   * 
   * The current implementation returns the payload as-is,
   * but can be customized for specific deserialization needs.
   * 
   * @example
   * ```typescript
   * // Custom deserialization example
   * deserializeUser(payload, done) {
   *   // Fetch full user data from database
   *   this.usersService.findById(payload.id)
   *     .then(user => done(null, user))
   *     .catch(error => done(error, null));
   * }
   * ```
   */
  deserializeUser(
    payload: any,
    done: (err: Error | null, payload: any) => void
  ): void {
    done(null, payload)
  }
}