import { UserDocument, UsersService } from '@hsuite/users'
import { User } from '@hsuite/users-types'
import { Injectable } from '@nestjs/common'
import * as lodash from 'lodash';
import { Auth } from '@hsuite/auth-types'

/**
 * Service responsible for authentication-related operations.
 * 
 * @description
 * This service handles core authentication functionality including:
 * - User profile retrieval
 * - Authentication state management
 * - Session handling for both Web2 and Web3 authentication
 * 
 * It works in conjunction with the UsersService to manage user data
 * and authentication states across different authentication methods.
 */
@Injectable()
export class AuthService {
    /**
     * Creates an instance of AuthService.
     * 
     * @constructor
     * @param {UsersService} usersService - Service for user-related operations
     */
    constructor(
        private usersService: UsersService
    ) {}
    
    /**
     * Retrieves the profile of an authenticated user.
     * 
     * @description
     * This method handles different authentication scenarios:
     * - Direct user ID lookup (_id field)
     * - Session-based user data retrieval
     * 
     * For user ID lookups, it fetches the complete user document
     * and removes sensitive information before returning.
     * For session-based lookups, it returns the existing session data.
     * 
     * @async
     * @param {any} user - User object containing either _id or session data
     * @returns {Promise<User.Safe | Auth.Credentials.Web3.Entity | Auth.Credentials.Web3.Response.Login>}
     * User profile in the appropriate format based on authentication type
     * @throws {Error} If user retrieval fails or user data is invalid
     * 
     * @example
     * ```typescript
     * // Retrieve profile by user ID
     * const profile = await authService.profile({ _id: 'user123' });
     * 
     * // Retrieve profile from session
     * const profile = await authService.profile({ session: {...} });
     * ```
     */
    async profile(user: any): Promise<User.Safe | Auth.Credentials.Web3.Entity | Auth.Credentials.Web3.Response.Login> {
        return new Promise(async (resolve, reject) => {
            try {
                // Initialize user session as null
                let userSession = null;

                // Handle different user object scenarios
                switch(true) {
                    case !lodash.isUndefined(user._id):
                        // If user has _id, fetch full user document
                        let userDocument: UserDocument = await this.usersService.findById(user._id);
                        // Remove password from user data for security
                        const { password, ...userSafe } = userDocument;
                        userSession = userSafe;
                        break;
                    case !lodash.isUndefined(user.session):
                        // If user already has session data, use it directly
                        userSession = user;
                        break;
                }

                resolve(userSession);
            } catch (error) {
                reject(error);
            }
        })
    }
}
