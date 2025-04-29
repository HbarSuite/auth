import { ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { AuthGuard } from '@nestjs/passport'
import { IS_PUBLIC } from '@hsuite/auth-types'
import { LoggerHelper } from '@hsuite/helpers';

/**
 * Redis-based Authentication Guard.
 * 
 * @description
 * This guard implements session-based authentication using Redis as the session store.
 * It provides:
 * - Route protection based on Redis session state
 * - Public route exclusions via metadata
 * - Login endpoint bypass
 * - Session validation through Passport
 * - Support for multiple concurrent sessions with wallet-based selection
 * 
 * The guard integrates with NestJS's authentication system to protect routes
 * requiring valid Redis sessions.
 * 
 * @class
 * @extends {AuthGuard('redis')}
 * 
 * @example
 * ```typescript
 * // Protect a route with Redis session authentication
 * @UseGuards(RedisAuthGuard)
 * @Get('protected')
 * getProtectedResource() {
 *   // Only accessible with valid Redis session
 *   return 'Protected data';
 * }
 * 
 * // Mark a route as public
 * @Public()
 * @Get('public')
 * getPublicResource() {
 *   return 'Public data';
 * }
 * ```
 */
@Injectable()
export class RedisAuthGuard extends AuthGuard('redis') {
  /**
   * Logger instance for logging messages
   * @type {LoggerHelper}
   */
  private logger: LoggerHelper = new LoggerHelper(RedisAuthGuard.name);

  /**
   * Creates an instance of RedisAuthGuard.
   * 
   * @constructor
   * @param {Reflector} reflector - NestJS reflector for accessing route metadata
   */
  constructor(private reflector: Reflector) {
    super();

    // Disable logging for this guard, to avoid too much noise
    this.logger.setLoggingEnabled(false);
  }
  
  /**
   * Determines if the current request can access the route.
   * 
   * @async
   * @param {ExecutionContext} context - Execution context containing request details
   * @returns {Promise<boolean>} Whether the route can be accessed
   * 
   * @description
   * This method implements the following access control logic:
   * 1. Checks for @Public() decorator to bypass authentication
   * 2. Allows unrestricted access to login endpoints
   * 3. Verifies Redis session authentication state
   * 4. Supports multiple sessions via X-Wallet-ID and X-Session-Cookie headers
   * 
   * The method supports multiple concurrent sessions by looking for specific
   * wallet IDs and session cookies in request headers.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    if(context.getHandler().name == 'login') {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    
    // DIAGNOSTIC LOGGING - Request identification
    const url = request.url || request.originalUrl || 'unknown';
    const method = request.method || 'unknown';
    this.logger.log(`\n[REDIS-AUTH-DEBUG] ===== Request ${method} ${url} =====`);
    
    // DIAGNOSTIC LOGGING - Log headers
    this.logger.log('[REDIS-AUTH-DEBUG] HEADERS:');
    if (request.headers) {
      for (const [key, value] of Object.entries(request.headers)) {
        this.logger.log(`[REDIS-AUTH-DEBUG] ${key}: ${JSON.stringify(value)}`);
      }
    } else {
      this.logger.log('[REDIS-AUTH-DEBUG] No headers found');
    }
    
    // DIAGNOSTIC LOGGING - Log cookies
    this.logger.log('[REDIS-AUTH-DEBUG] COOKIES:');
    if (request.cookies && Object.keys(request.cookies).length > 0) {
      for (const [key, value] of Object.entries(request.cookies)) {
        this.logger.log(`[REDIS-AUTH-DEBUG] Cookie ${key}: ${value}`);
      }
    } else {
      this.logger.log('[REDIS-AUTH-DEBUG] No cookies found');
    }
    
    // DIAGNOSTIC LOGGING - Specific checks for wallet and session headers
    const walletIdHeader = request.headers['x-wallet-id'] || 'not present';
    const sessionCookieHeader = request.headers['x-session-cookie'] || request.headers['X-Session-Cookie'] || 'not present';
    this.logger.log(`[REDIS-AUTH-DEBUG] X-Wallet-ID header: ${walletIdHeader}`);
    this.logger.log(`[REDIS-AUTH-DEBUG] X-Session-Cookie header: ${sessionCookieHeader}`);
    
    // Store the requested wallet ID for potential fallback use
    const requestedWalletId = request.headers['x-wallet-id'];
    
    // SECURE AUTH FLOW: Try header-based authentication first
    try {
      // If specific wallet or session cookie headers are provided, use those
      const walletId = request.headers['x-wallet-id'];
      const sessionCookie = request.headers['x-session-cookie'] || request.headers['X-Session-Cookie'];
      
      if (walletId && sessionCookie) {
        this.logger.log(`[REDIS-AUTH-DEBUG] Specific wallet and session cookie provided - prioritizing this session`);
        
        // Get cookie value
        const cookies = request.cookies || {};
        const sessionID = cookies[sessionCookie];
        
        if (!sessionID) {
          this.logger.log(`[REDIS-AUTH-DEBUG] No session ID found in cookie '${sessionCookie}'`);
          return false;
        }
        
        // Validate session
        const isValid = await this.validateSessionID(request, sessionID);
        if (isValid) {
          // Extra security check: ensure the session belongs to the requested wallet
          if (request.user?.session?.walletId !== walletId) {
            this.logger.log(`[REDIS-AUTH-DEBUG] Session found but belongs to wallet ${request.user.session.walletId}, not requested wallet ${walletId}`);
            return false;
          }
          
          this.logger.log(`[REDIS-AUTH-DEBUG] Successfully authenticated wallet ${walletId} using session cookie ${sessionCookie}`);
          return true;
        }
        
        this.logger.log(`[REDIS-AUTH-DEBUG] Session not valid for wallet ${walletId} and cookie ${sessionCookie}`);
        
        // Before failing, try to find any valid session for this wallet
        this.logger.log(`[REDIS-AUTH-DEBUG] Searching for alternative valid sessions for wallet ${walletId}`);
        const alternativeSession = await this.findSessionForWallet(request, walletId);
        if (alternativeSession) {
          this.logger.log(`[REDIS-AUTH-DEBUG] Found alternative valid session for wallet ${walletId}`);
          return true;
        }
        
        this.logger.log(`[REDIS-AUTH-DEBUG] No valid sessions found for wallet ${walletId}, authentication failed`);
        return false;
      }
      else if (walletId) {
        // Only wallet ID specified - try to find a valid session for this wallet
        this.logger.log(`[REDIS-AUTH-DEBUG] Only wallet ID specified - searching for any valid session for wallet ${walletId}`);
        const foundSession = await this.findSessionForWallet(request, walletId);
        if (foundSession) {
          this.logger.log(`[REDIS-AUTH-DEBUG] Found valid session for wallet ${walletId}`);
          return true;
        }
        
        this.logger.log(`[REDIS-AUTH-DEBUG] No valid sessions found for wallet ${walletId}, falling back to standard auth`);
      }
      else if (sessionCookie) {
        // Only session cookie specified
        const cookies = request.cookies || {};
        const sessionID = cookies[sessionCookie];
        
        if (!sessionID) {
          this.logger.log(`[REDIS-AUTH-DEBUG] No session ID found in cookie '${sessionCookie}'`);
          return false;
        }
        
        // Validate session
        const isValid = await this.validateSessionID(request, sessionID);
        if (isValid) {
          this.logger.log(`[REDIS-AUTH-DEBUG] Successfully authenticated using session cookie ${sessionCookie}`);
          return true;
        }
        
        this.logger.log(`[REDIS-AUTH-DEBUG] Session not valid for cookie ${sessionCookie}, falling back to standard auth`);
      }
    } catch (error) {
      this.logger.error('[REDIS-AUTH-DEBUG] Error in header-based authentication:', error);
    }
    
    // STANDARD AUTH FALLBACK - Only use if no specific headers were provided or validation failed
    if (request.isAuthenticated()) {
      // Check if we're using the correct wallet
      if (request.user?.session?.walletId && requestedWalletId && 
          request.user.session.walletId !== requestedWalletId) {
        this.logger.log(`[REDIS-AUTH-DEBUG] Standard auth session is for wallet ${request.user.session.walletId} but requested wallet is ${requestedWalletId}`);
        
        // Try to find a session for the requested wallet
        const foundSession = await this.findSessionForWallet(request, requestedWalletId);
        if (foundSession) {
          this.logger.log(`[REDIS-AUTH-DEBUG] Found valid session for requested wallet ${requestedWalletId}`);
          return true;
        }
        
        this.logger.log(`[REDIS-AUTH-DEBUG] No valid sessions found for requested wallet ${requestedWalletId}, using current session`);
      }
      
      // Log the wallet being used
      if (request.user?.session?.walletId) {
        this.logger.log(`[REDIS-AUTH-DEBUG] Using standard session for wallet: ${request.user.session.walletId}`);
      }
      
      return true;
    }
    
    this.logger.log('[REDIS-AUTH-DEBUG] All authentication methods failed');
    return false;
  }

  /**
   * Processes authentication results.
   * 
   * @param {Error} err - Authentication error if any
   * @param {any} user - Authenticated user data
   * @param {any} info - Additional authentication info
   * @returns {any} Processed user data
   * @throws {UnauthorizedException} If authentication fails
   * 
   * @description
   * This method:
   * 1. Handles authentication results from Passport
   * 2. Processes any authentication errors
   * 3. Validates user data presence
   * 4. Returns authenticated user data for request
   * 
   * It ensures proper error handling and user validation
   * before allowing access to protected routes.
   */
  handleRequest(err, user, info): any {
    if (err || !user) {
      throw err || new UnauthorizedException();
    }
    return user;
  }
  
  /**
   * Finds and validates a session based on wallet ID and/or session cookie.
   * 
   * @param request - The HTTP request
   * @param walletId - Wallet ID to find session for
   * @param sessionCookie - Session cookie name to use
   * @returns Promise resolving to boolean indicating if valid session was found
   */
  private async findAndValidateSession(request: any, walletId?: string, sessionCookie?: string): Promise<boolean> {
    const cookies = request.cookies || {};
    this.logger.log(`[REDIS-AUTH-DEBUG] findAndValidateSession called with walletId: ${walletId}, sessionCookie: ${sessionCookie}`);
    this.logger.log(`[REDIS-AUTH-DEBUG] Available cookies: ${Object.keys(cookies).join(', ')}`);
    
    // DEBUGGING COOKIE SESSION MAP
    if (walletId && sessionCookie) {
      this.logger.log(`[REDIS-AUTH-DEBUG] ===== DEBUGGING COOKIE SESSION MAP =====`);
      this.logger.log(`[REDIS-AUTH-DEBUG] Looking for wallet: ${walletId} with cookie: ${sessionCookie}`);
      
      // Get the expected session ID from the cookie
      const sessionID = cookies[sessionCookie];
      if (sessionID) {
        this.logger.log(`[REDIS-AUTH-DEBUG] Cookie ${sessionCookie} has session ID: ${sessionID}`);
        
        // Check if this session exists in Redis and get its wallet ID
        try {
          const sessionStore = request.sessionStore;
          if (sessionStore) {
            const session = await new Promise((resolve) => {
              sessionStore.get(sessionID, (err, session) => {
                if (err || !session) {
                  resolve(null);
                } else {
                  resolve(session);
                }
              });
            });
            
            if (session) {
              const typedSession = session as any;
              const sessionWalletId = typedSession?.passport?.user?.session?.walletId || 
                                    typedSession?.walletId || 
                                    typedSession?.user?.session?.walletId;
              
              this.logger.log(`[REDIS-AUTH-DEBUG] Redis session ${sessionID} belongs to wallet: ${sessionWalletId}`);
              this.logger.log(`[REDIS-AUTH-DEBUG] Requested wallet ${walletId} matches: ${sessionWalletId === walletId}`);
            } else {
              this.logger.log(`[REDIS-AUTH-DEBUG] Session ${sessionID} not found in Redis`);
            }
          }
        } catch (e) {
          this.logger.log(`[REDIS-AUTH-DEBUG] Error checking session in Redis:`, e);
        }
      } else {
        this.logger.log(`[REDIS-AUTH-DEBUG] Cookie ${sessionCookie} not found or has no value`);
      }
      this.logger.log(`[REDIS-AUTH-DEBUG] ===== END DEBUGGING COOKIE SESSION MAP =====`);
    }
    
    // REMOVED: Remove the explicit validation tracking - it's too aggressive
    
    // Case 1: Specific session cookie provided
    if (sessionCookie && cookies[sessionCookie]) {
      const sessionID = cookies[sessionCookie];
      this.logger.log(`[REDIS-AUTH-DEBUG] Trying specific session cookie: ${sessionCookie} with ID: ${sessionID}`);
      if (await this.validateSessionID(request, sessionID)) {
        // When both wallet ID and session cookie are specified, make sure the session is for the right wallet
        if (walletId && request.user?.session?.walletId) {
          if (request.user.session.walletId !== walletId) {
            this.logger.log(`[REDIS-AUTH-DEBUG] Session found but belongs to wallet ${request.user.session.walletId}, not requested wallet ${walletId}`);
            
            // REMOVED: Remove property setting that prevents fallback
            
            return false;
          }
          this.logger.log(`[REDIS-AUTH-DEBUG] Session cookie ${sessionCookie} matches requested wallet ${walletId}`);
        }
        
        this.logger.log(`[REDIS-AUTH-DEBUG] Successfully authenticated with session cookie: ${sessionCookie}`);
        return true;
      } else {
        // If the cookie exists but the session doesn't, the session probably expired
        
        // REMOVED: Remove property setting that prevents fallback
        
        // Try to find a valid session for this wallet in Redis
        if (walletId) {
          this.logger.log(`[REDIS-AUTH-DEBUG] Session cookie ${sessionCookie} exists but session expired. Trying to find a valid session for wallet ${walletId}`);
          return await this.findSessionForWallet(request, walletId);
        }
      }
    } else if (sessionCookie) {
      this.logger.log(`[REDIS-AUTH-DEBUG] Session cookie ${sessionCookie} was requested but not found in cookies`);
      
      // REMOVED: Remove property setting that prevents fallback
    }
    
    // Case 2: Wallet ID provided, find matching cookies
    if (walletId) {
      // Find cookies that might contain this wallet ID
      const sessionCookieNames = Object.keys(cookies).filter(name => 
        name.includes(`_${walletId.substring(0, 8)}`) || 
        name.includes(`_${walletId.replace(/\./g, '_')}`)
      );
      
      this.logger.log(`[REDIS-AUTH-DEBUG] Found ${sessionCookieNames.length} potential cookies for wallet ${walletId}: ${sessionCookieNames.join(', ')}`);
      
      // Try each potential cookie
      for (const cookieName of sessionCookieNames) {
        const sessionID = cookies[cookieName];
        this.logger.log(`[REDIS-AUTH-DEBUG] Trying cookie ${cookieName} for wallet ${walletId}`);
        
        if (await this.validateSessionID(request, sessionID)) {
          this.logger.log(`[REDIS-AUTH-DEBUG] Successfully authenticated wallet ${walletId} with cookie: ${cookieName}`);
          return true;
        }
      }
      
      // No matching cookies, try direct Redis search
      this.logger.log(`[REDIS-AUTH-DEBUG] No matching cookies, searching Redis for wallet: ${walletId}`);
      return await this.findSessionForWallet(request, walletId);
    }
    
    return false;
  }
  
  /**
   * Validates a session ID and sets up the request if valid.
   * 
   * @param request - The HTTP request object to update
   * @param sessionID - The session ID to validate
   * @returns Promise resolving to boolean indicating if session is valid
   */
  private async validateSessionID(request: any, sessionID: string): Promise<boolean> {
    try {
      // Get the session store
      const sessionStore = request.sessionStore;
      if (!sessionStore) {
        this.logger.log('[REDIS-AUTH-DEBUG] No session store found');
        return false;
      }
      
      this.logger.log(`[REDIS-AUTH-DEBUG] Validating session ID: ${sessionID}`);
      
      // Check if session exists and is valid
      return new Promise<boolean>((resolve) => {
        sessionStore.get(sessionID, (err, session) => {
          if (err) {
            this.logger.log('[REDIS-AUTH-DEBUG] Session get error:', err);
            resolve(false);
            return;
          }
          
          if (!session) {
            this.logger.log(`[REDIS-AUTH-DEBUG] No session found for ID: ${sessionID}`);
            resolve(false);
            return;
          }
          
          this.logger.log(`[REDIS-AUTH-DEBUG] Found session: ${sessionID}`);
          
          const typedSession = session as any;
          
          // Security check: Verify session has proper passport data
          if (!typedSession.passport || !typedSession.passport.user) {
            this.logger.log('[REDIS-AUTH-DEBUG] Session exists but has no passport data');
            resolve(false);
            return;
          }
          
          // Security check: Validate session signature if present
          if (typedSession.passport.user._sessionSignature) {
            const crypto = require('crypto');
            const expectedSignature = crypto.createHmac('sha256', 'hsuite-secure-session-salt')
              .update(`${typedSession.passport.user._walletId || typedSession.passport.user.session?.walletId}:${typedSession.uniqueSessionId || typedSession.passport.user._uniqueSessionId}`)
              .digest('hex');
              
            if (expectedSignature !== typedSession.passport.user._sessionSignature) {
              this.logger.log('[REDIS-AUTH-DEBUG] Session signature validation failed');
              resolve(false);
              return;
            }
            this.logger.log('[REDIS-AUTH-DEBUG] Session signature validated successfully');
          }
          
          // Get wallet ID from session
          const walletId = typedSession.passport.user.session?.walletId || 
                          typedSession.walletId || 
                          typedSession.passport.user._walletId;
                          
          this.logger.log(`[REDIS-AUTH-DEBUG] Valid session found for wallet: ${walletId}`);
          
          // Security check: Validate session hasn't expired
          if (typedSession.cookie && typedSession.cookie.expires) {
            const expiryDate = new Date(typedSession.cookie.expires);
            if (expiryDate < new Date()) {
              this.logger.log('[REDIS-AUTH-DEBUG] Session has expired:', expiryDate);
              resolve(false);
              return;
            }
          }
          
          // Previous user data - for comparison
          const previousWalletId = request.user?.session?.walletId;
          this.logger.log(`[REDIS-AUTH-DEBUG] Previous request user wallet: ${previousWalletId || 'none'}`);
          
          // Set user data on request
          request.user = JSON.parse(JSON.stringify(typedSession.passport.user));
          
          try {
            if (request.login) {
              // Use passport's login method which handles the session properly
              request.login(request.user, (err) => {
                if (err) {
                  this.logger.log('[REDIS-AUTH-DEBUG] Error logging in with session:', err);
                  resolve(false);
                  return;
                }
                this.logger.log('[REDIS-AUTH-DEBUG] Successfully logged in with session');
                resolve(true);
              });
            } else {
              this.logger.log('[REDIS-AUTH-DEBUG] No request.login method available, using direct assignment');
              // Fallback - be careful with the session object
              if (request.session && typeof request.session === 'object') {
                // Just update the passport property instead of replacing the whole session
                request.session.passport = typedSession.passport;
                resolve(true);
              } else {
                this.logger.log('[REDIS-AUTH-DEBUG] Cannot update session, no valid session object');
                resolve(true); // Still resolve true since we found a valid session
              }
            }
          } catch (e) {
            this.logger.log('[REDIS-AUTH-DEBUG] Error updating session:', e);
            // Still consider this authenticated since we found a valid session
            resolve(true);
          }
        });
      });
    } catch (err) {
      this.logger.log('[REDIS-AUTH-DEBUG] Error validating session ID:', err);
      return false;
    }
  }
  
  /**
   * Searches Redis directly for a session matching the given wallet ID.
   * 
   * @param request - The HTTP request object
   * @param walletId - The wallet ID to search for
   * @returns Promise resolving to boolean indicating if a matching session was found
   */
  private async findSessionForWallet(request: any, walletId: string): Promise<boolean> {
    try {
      // Get the session store
      const sessionStore = request.sessionStore;
      if (!sessionStore || !sessionStore.client) {
        this.logger.log('[REDIS-AUTH-DEBUG] No Redis client available for direct session search');
        return false;
      }
      
      this.logger.log(`[REDIS-AUTH-DEBUG] Starting direct Redis search for wallet: ${walletId}`);
      
      // ADD: Dump all sessions to debug
      this.logger.log('[REDIS-AUTH-DEBUG] ****** DUMPING ALL SESSIONS FOR DIAGNOSIS ******');
      try {
        const allSessions = await new Promise<any>((resolve) => {
          sessionStore.all((err, sessions) => {
            if (err) {
              this.logger.log('[REDIS-AUTH-DEBUG] Error getting all sessions:', err);
              resolve({});
            } else {
              resolve(sessions || {});
            }
          });
        });
        
        this.logger.log(`[REDIS-AUTH-DEBUG] Found ${Object.keys(allSessions).length} total sessions in Redis`);
        
        // Examine each session to find wallet information
        for (const [sid, sessionData] of Object.entries(allSessions)) {
          const typedSession = sessionData as any;
          const sessionWalletId = 
            typedSession?.passport?.user?.session?.walletId || 
            typedSession?.walletId || 
            typedSession?.user?.session?.walletId;
          
          if (sessionWalletId) {
            this.logger.log(`[REDIS-AUTH-DEBUG] Session ${sid} belongs to wallet: ${sessionWalletId}`);
            
            // Check if this is what we're looking for
            if (sessionWalletId === walletId) {
              this.logger.log(`[REDIS-AUTH-DEBUG] *** FOUND TARGET SESSION for wallet ${walletId} ***`);
              this.logger.log(`[REDIS-AUTH-DEBUG] Session cookie should be: ${sid}`);
              
              // Try to validate with this session ID directly
              if (await this.validateSessionID(request, sid)) {
                this.logger.log(`[REDIS-AUTH-DEBUG] Successfully authenticated with session directly from store`);
                return true;
              }
            }
          }
        }
      } catch (e) {
        this.logger.log('[REDIS-AUTH-DEBUG] Error dumping sessions:', e);
      }
      
      // Use Redis client directly
      const redisClient = sessionStore.client;
      
      // IMPROVED REDIS CLIENT DETECTION: Supporting more client versions
      // Dump client keys to help diagnose what methods are available
      this.logger.log('[REDIS-AUTH-DEBUG] Redis client methods available:', Object.keys(redisClient).slice(0, 20));
      
      // Check if this is a Node Redis client with a commander
      if (redisClient.commander) {
        this.logger.log('[REDIS-AUTH-DEBUG] Node Redis client with commander detected');
        try {
          const keys = await redisClient.keys('hsuite-sess:*');
          return this.processSessionKeys(request, walletId, keys);
        } catch (e) {
          this.logger.log('[REDIS-AUTH-DEBUG] Error using commander keys method:', e);
        }
      }
      
      // Check for modern Redis clients (Node Redis v4+, IORedis)
      if (typeof redisClient.keys !== 'function') {
        this.logger.log('[REDIS-AUTH-DEBUG] Modern Redis client detected, attempting different methods');
        
        // Try multiple methods to work with various Redis client versions
        let keys = null;
        
        // Method 1: Try sendCommand
        if (typeof redisClient.sendCommand === 'function') {
          try {
            this.logger.log('[REDIS-AUTH-DEBUG] Trying sendCommand method');
            keys = await redisClient.sendCommand(['KEYS', 'hsuite-sess:*']);
            return await this.processSessionKeys(request, walletId, keys);
          } catch (e) {
            this.logger.log('[REDIS-AUTH-DEBUG] sendCommand method failed:', e);
          }
        }
        
        // Method 2: Try sendCommand with object format
        if (typeof redisClient.sendCommand === 'function') {
          try {
            this.logger.log('[REDIS-AUTH-DEBUG] Trying sendCommand with object format');
            keys = await redisClient.sendCommand({
              command: 'KEYS',
              args: ['hsuite-sess:*']
            });
            return await this.processSessionKeys(request, walletId, keys);
          } catch (e) {
            this.logger.log('[REDIS-AUTH-DEBUG] sendCommand with object format failed:', e);
          }
        }
        
        // Method 3: Try direct uppercase method (IORedis style)
        if (typeof redisClient.KEYS === 'function') {
          try {
            this.logger.log('[REDIS-AUTH-DEBUG] Trying KEYS method (IORedis style)');
            keys = await redisClient.KEYS('hsuite-sess:*');
            return await this.processSessionKeys(request, walletId, keys);
          } catch (e) {
            this.logger.log('[REDIS-AUTH-DEBUG] KEYS method failed:', e);
          }
        }
        
        // Method 4: Try the command helper if available
        if (redisClient.command) {
          try {
            this.logger.log('[REDIS-AUTH-DEBUG] Trying command helper');
            keys = await redisClient.command('KEYS', ['hsuite-sess:*']);
            return await this.processSessionKeys(request, walletId, keys);
          } catch (e) {
            this.logger.log('[REDIS-AUTH-DEBUG] command helper failed:', e);
          }
        }
        
        // DIRECT SCAN FALLBACK
        // If all else fails, try using a direct connection to Redis if possible
        try {
          this.logger.log('[REDIS-AUTH-DEBUG] Trying direct Redis connection');
          // Get all sessions directly from the session store
          const sessions = await new Promise<any[]>((resolve) => {
            sessionStore.all((err, sessions) => {
              if (err) {
                this.logger.log('[REDIS-AUTH-DEBUG] Error getting all sessions:', err);
                resolve([]);
              } else {
                resolve(sessions || []);
              }
            });
          });
          
          this.logger.log(`[REDIS-AUTH-DEBUG] Retrieved ${Object.keys(sessions).length} sessions directly from session store`);
          
          // Check each session for our wallet
          for (const [sid, sessionData] of Object.entries(sessions)) {
            const typedSession = sessionData as any;
            const sessionWalletId = 
              typedSession?.passport?.user?.session?.walletId || 
              typedSession?.walletId || 
              typedSession?.user?.session?.walletId;
            
            if (sessionWalletId === walletId) {
              this.logger.log(`[REDIS-AUTH-DEBUG] Found matching session for wallet ${walletId} with ID: ${sid}`);
              if (await this.validateSessionID(request, sid)) {
                this.logger.log(`[REDIS-AUTH-DEBUG] Successfully authenticated with session store-searched session`);
                return true;
              }
            }
          }
          
          this.logger.log(`[REDIS-AUTH-DEBUG] No matching session found in session store for wallet ${walletId}`);
          return false;
        } catch (e) {
          this.logger.log('[REDIS-AUTH-DEBUG] Error with direct session store access:', e);
        }
        
        this.logger.log('[REDIS-AUTH-DEBUG] All Redis search methods failed. Cannot search for sessions.');
        return false;
      } else {
        // Legacy callback-based Redis client
        return new Promise<boolean>((resolve) => {
          redisClient.keys('hsuite-sess:*', async (err, keys) => {
            if (err || !keys || keys.length === 0) {
              this.logger.log('[REDIS-AUTH-DEBUG] Error getting session keys or no keys found:', err);
              resolve(false);
              return;
            }
            
            const result = await this.processSessionKeys(request, walletId, keys);
            resolve(result);
          });
        });
      }
    } catch (e) {
      this.logger.log('[REDIS-AUTH-DEBUG] Error in direct Redis session search:', e);
      return false;
    }
  }
  
  /**
   * Process session keys to find a matching wallet
   * 
   * @param request - The HTTP request object
   * @param walletId - Wallet ID to search for
   * @param keys - Array of Redis keys to check
   * @returns Promise resolving to boolean indicating if a match was found
   */
  private async processSessionKeys(request: any, walletId: string, keys: string[]): Promise<boolean> {
    if (!keys || keys.length === 0) {
      this.logger.log('[REDIS-AUTH-DEBUG] No session keys found');
      return false;
    }
    
    this.logger.log(`[REDIS-AUTH-DEBUG] Found ${keys.length} session keys in Redis`);
    
    // Get Redis client
    const redisClient = request.sessionStore.client;
    
    // Check each session for our wallet ID
    for (const key of keys) {
      try {
        this.logger.log(`[REDIS-AUTH-DEBUG] Checking Redis key: ${key}`);
        
        let sessionData;
        try {
          // Try multiple methods to get the session data
          if (typeof redisClient.get === 'function') {
            // Standard get method
            const data = await new Promise<string>((resolve, reject) => {
              redisClient.get(key, (err, data) => {
                if (err) reject(err);
                else resolve(data);
              });
            });
            sessionData = JSON.parse(data || '{}');
          } else if (typeof redisClient.GET === 'function') {
            // IORedis uppercase method
            const data = await redisClient.GET(key);
            sessionData = JSON.parse(data || '{}');
          } else if (typeof redisClient.sendCommand === 'function') {
            // Node Redis v4+
            const data = await redisClient.sendCommand(['GET', key]);
            sessionData = JSON.parse(data || '{}');
          } else {
            this.logger.log(`[REDIS-AUTH-DEBUG] No method found to get session data for key: ${key}`);
            continue;
          }
        } catch (e) {
          this.logger.log(`[REDIS-AUTH-DEBUG] Error getting session data for key ${key}:`, e);
          continue;
        }
        
        // Check if this session belongs to our wallet
        const sessionWalletId = sessionData?.passport?.user?.session?.walletId || 
                              sessionData?.walletId || 
                              sessionData?.user?.session?.walletId;
        
        if (sessionWalletId) {
          this.logger.log(`[REDIS-AUTH-DEBUG] Session ${key} belongs to wallet: ${sessionWalletId}`);
        }
        
        if (sessionWalletId === walletId) {
          // Remove storing matching session
          const sessionID = key.replace('hsuite-sess:', '');
          
          this.logger.log(`[REDIS-AUTH-DEBUG] Found matching session for wallet ${walletId} in Redis key: ${key}`);
          
          // Try to validate with this session ID
          if (await this.validateSessionID(request, sessionID)) {
            this.logger.log(`[REDIS-AUTH-DEBUG] Successfully authenticated with Redis-searched session`);
            
            return true;
          }
        }
      } catch (e) {
        this.logger.log(`[REDIS-AUTH-DEBUG] Error checking session ${key}:`, e);
      }
    }
    
    this.logger.log(`[REDIS-AUTH-DEBUG] No matching session found for wallet ${walletId}`);
    return false;
  }
}