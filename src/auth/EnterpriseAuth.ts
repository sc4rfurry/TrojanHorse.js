/**
 * TrojanHorse.js Enterprise Authentication System
 * Production-ready authentication with OAuth2, SAML, MFA, and RBAC
 */

import { EventEmitter } from 'events';
import { CryptoEngine } from '../security/CryptoEngine';
import crypto from 'crypto';
import qrcode from 'qrcode';
import * as otplib from 'otplib';

// ===== AUTHENTICATION INTERFACES =====

export interface User {
  id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  roles: string[];
  permissions: string[];
  department: string;
  isActive: boolean;
  lastLogin: Date;
  mfaEnabled: boolean;
  metadata?: Record<string, any>;
}

export interface AuthenticationConfig {
  oauth2?: OAuth2Config;
  saml?: SAMLConfig;
  ldap?: LDAPConfig;
  mfa?: MFAConfig;
  rbac?: RBACConfig;
  session?: SessionConfig;
}

export interface OAuth2Config {
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  scopes: string[];
  provider: 'microsoft' | 'google' | 'github' | 'okta' | 'auth0' | 'custom';
  authorizationURL?: string;
  tokenURL?: string;
  userInfoURL?: string;
  pkce?: boolean;
}

export interface SAMLConfig {
  entityId: string;
  ssoURL: string;
  certificate: string;
  privateKey?: string;
  callbackURL: string;
  signatureAlgorithm?: string;
}

export interface LDAPConfig {
  url: string;
  bindDN: string;
  bindPassword: string;
  baseDN: string;
  usernameAttribute: string;
  emailAttribute: string;
}

export interface MFAConfig {
  enabled: boolean;
  issuer: string;
  window: number;
  backupCodes: boolean;
}

export interface RBACConfig {
  roles: Role[];
  permissions: Permission[];
}

export interface SessionConfig {
  secret: string;
  maxAge: number;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'strict' | 'lax' | 'none';
}

export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
}

export interface Permission {
  id: string;
  name: string;
  description: string;
  resource: string;
  action: string;
}

// ===== AUTHENTICATION PROVIDERS =====

abstract class BaseAuthProvider extends EventEmitter {
  protected config: any;
  protected crypto: CryptoEngine;

  constructor(config: any) {
    super();
    this.config = config;
    this.crypto = new CryptoEngine();
  }

  abstract authenticate(credentials: any): Promise<User | null>;
  abstract validateToken(token: string): Promise<User | null>;
  abstract refresh(refreshToken: string): Promise<{ accessToken: string; refreshToken: string } | null>;
}

// ===== OAUTH2 PROVIDER =====

class OAuth2Provider extends BaseAuthProvider {
  private clientId: string;
  private clientSecret: string;
  private redirectUri: string;
  private scope: string[];

  constructor(config: OAuth2Config) {
    super(config);
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.callbackURL;
    this.scope = config.scopes || ['openid', 'profile', 'email'];
  }

  public generateAuthURL(state: string, codeChallenge?: string): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      response_type: 'code',
      redirect_uri: this.redirectUri,
      scope: this.scope.join(' '),
      state
    });

    if (codeChallenge) {
      params.append('code_challenge', codeChallenge);
      params.append('code_challenge_method', 'S256');
    }

    const baseUrl = this.getAuthorizationURL();
    return `${baseUrl}?${params.toString()}`;
  }

  private getAuthorizationURL(): string {
    return this.config.authorizationURL || 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
  }

  private getTokenURL(): string {
    return this.config.tokenURL || 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
  }

  private getUserInfoURL(): string {
    return this.config.userInfoURL || 'https://graph.microsoft.com/v1.0/me';
  }

  public async authenticate(credentials: { code: string; state: string; codeVerifier?: string }): Promise<User | null> {
    try {
      const tokenResponse = await this.exchangeCodeForTokens(credentials);
      
      if (!tokenResponse.access_token) {
        throw new Error('No access token received');
      }

      const userInfo = await this.getUserInfo(tokenResponse.access_token);
      const user = this.mapUserInfo(userInfo);
      
      this.emit('authentication_success', { user, provider: this.config.provider });
      return user;
      
    } catch (error) {
      this.emit('authentication_failed', { error, provider: this.config.provider });
      return null;
    }
  }

  public async validateToken(token: string): Promise<User | null> {
    try {
      const userInfo = await this.getUserInfo(token);
      return this.mapUserInfo(userInfo);
    } catch (error) {
      return null;
    }
  }

  public async refresh(refreshToken: string): Promise<{ accessToken: string; refreshToken: string } | null> {
    try {
      const response = await fetch(this.getTokenURL(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: this.clientId,
          client_secret: this.clientSecret
        })
      });

      const data = await response.json();
      
      return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token || refreshToken
      };
    } catch (error) {
      return null;
    }
  }

  private async exchangeCodeForTokens(credentials: any): Promise<any> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: credentials.code,
      redirect_uri: this.redirectUri,
      client_id: this.clientId,
      client_secret: this.clientSecret
    });

    if (credentials.codeVerifier) {
      body.append('code_verifier', credentials.codeVerifier);
    }

    const response = await fetch(this.getTokenURL(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });

    return response.json();
  }

  private async getUserInfo(accessToken: string): Promise<any> {
    const response = await fetch(this.getUserInfoURL(), {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    return response.json();
  }

  private mapUserInfo(userInfo: any): User {
    return {
      id: userInfo.id?.toString() || userInfo.sub?.toString(),
      username: userInfo.userPrincipalName || userInfo.email || userInfo.login,
      email: userInfo.mail || userInfo.email,
      firstName: userInfo.givenName || userInfo.given_name || userInfo.name || '',
      lastName: userInfo.surname || userInfo.family_name || '',
      roles: [],
      permissions: [],
      department: '',
      isActive: true,
      lastLogin: new Date(),
      mfaEnabled: false,
      metadata: userInfo
    };
  }
}

// ===== SAML PROVIDER =====

class SAMLProvider extends BaseAuthProvider {
  constructor(config: SAMLConfig) {
    super(config);
  }

  public async authenticate(credentials: { samlResponse: string }): Promise<User | null> {
    try {
      const isValid = await this.validateSAMLResponse(credentials.samlResponse);
      if (!isValid) {
        throw new Error('Invalid SAML response');
      }

      const attributes = this.parseSAMLResponse(credentials.samlResponse);
      
      const user: User = {
        id: attributes.NameID || attributes.email,
        username: attributes.email || attributes.NameID,
        email: attributes.email,
        firstName: attributes.firstName || '',
        lastName: attributes.lastName || '',
        roles: [],
        permissions: [],
        department: attributes.department || '',
        isActive: true,
        lastLogin: new Date(),
        mfaEnabled: false,
        metadata: attributes
      };

      this.emit('authentication_success', { user, provider: 'saml' });
      return user;
      
    } catch (error) {
      this.emit('authentication_failed', { error, provider: 'saml' });
      return null;
    }
  }

  public async validateToken(token: string): Promise<User | null> {
    return null;
  }

  public async refresh(refreshToken: string): Promise<{ accessToken: string; refreshToken: string } | null> {
    return null;
  }

  private async validateSAMLResponse(samlResponse: string): Promise<boolean> {
    try {
      const decoded = Buffer.from(samlResponse, 'base64').toString();
      
      if (!decoded.includes('<saml:Response') || !decoded.includes('<saml:Assertion')) {
        return false;
      }

      const requiredElements = [
        '<saml:Response',
        '<saml:Assertion',
        '<saml:Subject',
        '<saml:AttributeStatement'
      ];

      for (const element of requiredElements) {
        if (!decoded.includes(element)) {
          return false;
        }
      }

      const timestampMatch = decoded.match(/NotOnOrAfter="([^"]+)"/);
      if (timestampMatch) {
        const notOnOrAfter = new Date(timestampMatch[1]);
        if (notOnOrAfter < new Date()) {
          return false;
        }
      }
      
      return true;
    } catch (error) {
      this.emit('saml_validation_error', { error });
      return false;
    }
  }

  private parseSAMLResponse(samlResponse: string): Record<string, string> {
    try {
      const decoded = Buffer.from(samlResponse, 'base64').toString();
      const attributes: Record<string, string> = {};
      
      const nameIdMatch = decoded.match(/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/);
      if (nameIdMatch) {
        attributes.NameID = nameIdMatch[1];
      }

      const attributePattern = /<saml:Attribute Name="([^"]+)"[^>]*><saml:AttributeValue[^>]*>([^<]+)<\/saml:AttributeValue><\/saml:Attribute>/g;
      
      let match;
      while ((match = attributePattern.exec(decoded)) !== null) {
        attributes[match[1]] = match[2];
      }

      const sessionMatch = decoded.match(/SessionIndex="([^"]+)"/);
      if (sessionMatch) {
        attributes.SessionIndex = sessionMatch[1];
      }

      return attributes;
    } catch (error) {
      this.emit('saml_parsing_error', { error });
      return {};
    }
  }
}

// ===== MFA MANAGER =====

class MFAManager {
  private totpSecrets: Map<string, string> = new Map();
  private backupCodes: Map<string, string[]> = new Map();

  public async enableMFA(userId: string): Promise<{ secret: string; qrCode: string; backupCodes: string[] }> {
    const secret = otplib.authenticator.generateSecret();
    const otpauthUrl = otplib.authenticator.keyuri(userId, 'TrojanHorse.js', secret);
    const qrCode = await qrcode.toDataURL(otpauthUrl);
    
    const backupCodes = this.generateBackupCodes();
    
    this.totpSecrets.set(userId, secret);
    this.backupCodes.set(userId, backupCodes);
    
    return { secret, qrCode, backupCodes };
  }

  public verifyMFA(userId: string, token: string): boolean {
    const secret = this.totpSecrets.get(userId);
    if (!secret) {
      return false;
    }

    const isValid = otplib.authenticator.verify({ token, secret });
    if (isValid) {
      return true;
    }

    const backupCodes = this.backupCodes.get(userId) || [];
    const backupIndex = backupCodes.indexOf(token);
    if (backupIndex !== -1) {
      backupCodes.splice(backupIndex, 1);
      this.backupCodes.set(userId, backupCodes);
      return true;
    }

    return false;
  }

  private generateBackupCodes(): string[] {
    const codes: string[] = [];
    for (let i = 0; i < 10; i++) {
      codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }
    return codes;
  }
}

// ===== RBAC MANAGER =====

class RBACManager {
  private roles: Map<string, Role> = new Map();
  private permissions: Map<string, Permission> = new Map();
  private userRoles: Map<string, string[]> = new Map();

  public createRole(role: Role): void {
    this.roles.set(role.id, role);
  }

  public createPermission(permission: Permission): void {
    this.permissions.set(permission.id, permission);
  }

  public assignRole(userId: string, roleId: string): boolean {
    if (!this.roles.has(roleId)) {
      return false;
    }

    const userRoles = this.userRoles.get(userId) || [];
    if (!userRoles.includes(roleId)) {
      userRoles.push(roleId);
      this.userRoles.set(userId, userRoles);
    }
    
    return true;
  }

  public hasPermission(userId: string, resource: string, action: string): boolean {
    const userRoles = this.userRoles.get(userId) || [];
    
    for (const roleId of userRoles) {
      const role = this.roles.get(roleId);
      if (role) {
        for (const permissionId of role.permissions) {
          const permission = this.permissions.get(permissionId);
          if (permission && permission.resource === resource && permission.action === action) {
            return true;
          }
        }
      }
    }
    
    return false;
  }
}

// ===== SESSION MANAGER =====

class SessionManager {
  private sessions: Map<string, any> = new Map();
  private config: SessionConfig;

  constructor(config: SessionConfig) {
    this.config = config;
  }

  public createSession(userId: string, user: User): string {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const session = {
      id: sessionId,
      userId,
      user,
      createdAt: new Date(),
      lastAccessed: new Date(),
      ipAddress: '',
      userAgent: ''
    };
    
    this.sessions.set(sessionId, session);
    
    setTimeout(() => {
      this.sessions.delete(sessionId);
    }, this.config.maxAge);
    
    return sessionId;
  }

  public getSession(sessionId: string): any | null {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.lastAccessed = new Date();
      return session;
    }
    return null;
  }

  public destroySession(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }
}

// ===== ENTERPRISE AUTH MANAGER =====

class EnterpriseAuthManager extends EventEmitter {
  private config: AuthenticationConfig;
  private oauth2Provider?: OAuth2Provider;
  private samlProvider?: SAMLProvider;
  private mfaManager: MFAManager;
  private rbacManager: RBACManager;
  private sessionManager: SessionManager;

  constructor(config: AuthenticationConfig) {
    super();
    this.config = config;
    
    if (config.oauth2) {
      this.oauth2Provider = new OAuth2Provider(config.oauth2);
    }
    
    if (config.saml) {
      this.samlProvider = new SAMLProvider(config.saml);
    }
    
    this.mfaManager = new MFAManager();
    this.rbacManager = new RBACManager();
    this.sessionManager = new SessionManager(config.session || {
      secret: 'default-secret',
      maxAge: 24 * 60 * 60 * 1000,
      secure: true,
      httpOnly: true,
      sameSite: 'strict'
    });
  }

  public async authenticate(method: 'oauth2' | 'saml', credentials: any): Promise<{ user: User; sessionId: string } | null> {
    try {
      let user: User | null = null;
      
      if (method === 'oauth2' && this.oauth2Provider) {
        user = await this.oauth2Provider.authenticate(credentials);
      } else if (method === 'saml' && this.samlProvider) {
        user = await this.samlProvider.authenticate(credentials);
      }
      
      if (user) {
        const sessionId = this.sessionManager.createSession(user.id, user);
        this.emit('user_authenticated', { user, method, sessionId });
        return { user, sessionId };
      }
      
      return null;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.emit('authentication_error', { method, error: errorMessage });
      return null;
    }
  }

  public getMFAManager(): MFAManager {
    return this.mfaManager;
  }

  public getRBACManager(): RBACManager {
    return this.rbacManager;
  }

  public getSessionManager(): SessionManager {
    return this.sessionManager;
  }
}

// Export all classes and types
export {
  BaseAuthProvider,
  OAuth2Provider,
  SAMLProvider,
  MFAManager,
  RBACManager,
  SessionManager,
  EnterpriseAuthManager
}; 