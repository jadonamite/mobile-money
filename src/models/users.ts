export interface User {
  id: string;
  phone_number: string;
  email?: string;
  kyc_level: 'unverified' | 'basic' | 'full';
  role_name?: string;
  created_at: Date;
  updated_at: Date;
  
  // 2FA fields
  two_factor_secret?: string;
  two_factor_enabled: boolean;
  two_factor_verified: boolean;
  backup_codes?: BackupCode[];
}

export interface BackupCode {
  id: string;
  code_hash: string;
  used: boolean;
  created_at: Date;
  used_at?: Date;
}

export interface CreateUserRequest {
  phone_number: string;
  email?: string;
  kyc_level?: 'unverified' | 'basic' | 'full';
  role_name?: string;
}

export interface UpdateUserRequest {
  email?: string;
  kyc_level?: 'unverified' | 'basic' | 'full';
  role_name?: string;
  two_factor_secret?: string;
  two_factor_enabled?: boolean;
  two_factor_verified?: boolean;
}

export interface Enable2FARequest {
  two_factor_secret: string;
  backup_codes: string[];
}

export interface Verify2FARequest {
  token: string;
}

export interface BackupCodeVerification {
  valid: boolean;
  codeId?: string;
}