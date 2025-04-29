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
   * The implementation now includes unique session identifiers to ensure
   * multiple login sessions can be maintained for the same user.
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
    // Create a unique login session identifier
    const sessionData = {
      ...user,
      // Add required unique identifiers to distinguish between sessions
      _sessionTimestamp: user._sessionTimestamp || Date.now(),
      _sessionId: user.uniqueSessionId || user._sessionId || `sess_${Date.now()}_${require('crypto').randomBytes(8).toString('hex')}`,
      // Keep track of which wallet account owns this session
      _walletId: user.walletId || user.session?.walletId || user.operator?.accountId
    };
    
    // Handle session isolation by adding a unique signature
    if (user.signedData?.userSignature && !sessionData._loginSignature) {
      // Create a hash of the signature to identify this specific login
      const crypto = require('crypto');
      sessionData._loginSignature = crypto.createHash('sha256')
        .update(JSON.stringify(user.signedData.userSignature))
        .digest('hex');
    }
    
    done(null, sessionData);
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
   * The current implementation preserves the unique session identifiers
   * and session timestamps used to differentiate between multiple logins.
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
    // Preserve all session identifiers during deserialization
    const userData = {
      ...payload,
      // Ensure session isolation markers are preserved
      _isAuthenticated: true
    };
    
    done(null, userData);
  }
}