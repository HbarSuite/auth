/**
 * Authentication Module Entry Point
 * 
 * @description
 * This module provides comprehensive authentication functionality including:
 * - JWT and Redis-based authentication guards
 * - Session management and serialization
 * - Web2 (username/password) authentication with 2FA support
 * - Web3 (wallet-based) authentication
 * - Core authentication services and controllers
 * 
 * @module Auth
 */

// Interfaces
export * from './interfaces/auth-options.interface'

// Authentication Guards
export * from './guards/jwt.guard'           // JWT authentication guard
export * from './guards/redis.guard'         // Redis session-based guard
export * from './guards/confirmed.guard'     // Email confirmation guard

// Redis Authentication
export * from './redis/redis.constants'      // Redis configuration constants
export * from './redis/redis.module'         // Redis authentication module

// Session Management
export * from './serializers/session.serializer' // Session serialization

// Authentication Strategies  
export * from './strategies/jwt.strategy'    // JWT authentication strategy

// Core Authentication
export * from './auth.module'               // Main authentication module
export * from './auth.service'              // Core authentication service
export * from './auth.controller'           // Authentication controller

// Web2 Authentication
export * from './web2/src/index'           // Username/password authentication
export * from './web2/2fa/index'           // Two-factor authentication

// Web3 Authentication  
export * from './web3/src/index'           // Wallet-based authentication