import { Router, Request, Response } from 'express';
import { generateToken, verifyToken, JWTPayload } from '../auth/jwt';
import { 
  generateTOTPSecret, 
  generateQRCodeDataURL, 
  verifyTOTPToken, 
  validateTOTPSetup,
  generateBackupCodes,
  hashBackupCodes,
  verifyBackupCode,
  generateBackupCodeId,
  is2FAEnabled
} from '../auth/2fa';
import { authenticateUser, getUserById } from '../services/userService';
import { authenticateToken } from '../middleware/auth';
import { attachUserContext } from '../middleware/rbac';

export const authRoutes = Router();

/**
 * POST /api/auth/login
 * 
 * Login endpoint that generates a JWT token with role information
 * Uses phone number for authentication (simplified for demo)
 */
authRoutes.post('/login', async (req: Request, res: Response) => {
  const { phone_number } = req.body;

  // Basic validation
  if (!phone_number) {
    return res.status(400).json({
      error: 'Missing required fields',
      message: 'phone_number is required'
    });
  }

  try {
    // Authenticate user (creates user if doesn't exist)
    const user = await authenticateUser(phone_number);
    
    if (!user) {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid phone number'
      });
    }

    // Generate JWT token with role
    const token = generateToken({ 
      userId: user.id, 
      email: `${phone_number}@mobile-money.local`, // Generate email from phone
      role: user.role_name || 'user'
    });
    
    res.json({
      message: 'Login successful',
      token,
      user: {
        userId: user.id,
        phone_number: user.phone_number,
        kyc_level: user.kyc_level,
        role: user.role_name || 'user'
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'Login failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * POST /api/auth/verify
 * 
 * Verify a JWT token and return the decoded payload
 */
authRoutes.post('/verify', (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({
      error: 'Missing token',
      message: 'Token is required for verification'
    });
  }

  try {
    const payload = verifyToken(token);
    res.json({
      valid: true,
      payload
    });
  } catch (error) {
    res.status(401).json({
      valid: false,
      error: 'Token verification failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/auth/me
 * 
 * Protected route that returns current user information with role and permissions
 * Requires valid JWT token in Authorization header
 */
authRoutes.get('/me', authenticateToken, attachUserContext, async (req: Request, res: Response) => {
  try {
    if (!req.jwtUser) {
      return res.status(401).json({
        error: 'Access denied',
        message: 'No token provided'
      });
    }

    // Get full user information
    const user = await getUserById(req.jwtUser.userId);
    
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User associated with token no longer exists'
      });
    }

    res.json({
      user: {
        userId: user.id,
        phone_number: user.phone_number,
        kyc_level: user.kyc_level,
        role: user.role_name || 'user',
        permissions: req.userPermissions || []
      },
      tokenInfo: {
        issuedAt: req.jwtUser.iat,
        expiresAt: req.jwtUser.exp
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get user information',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * POST /api/auth/2fa/setup
 * 
 * Generate TOTP secret and QR code for 2FA setup
 * Requires authentication
 */
authRoutes.post('/2fa/setup', authenticateToken, async (req: Request, res: Response) => {
  try {
    if (!req.jwtUser) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Valid JWT token required'
      });
    }

    // Get user information
    const user = await getUserById(req.jwtUser.userId);
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User associated with token no longer exists'
      });
    }

    // Check if 2FA is already enabled
    if (is2FAEnabled(user)) {
      return res.status(400).json({
        error: '2FA already enabled',
        message: 'Two-factor authentication is already enabled for this account'
      });
    }

    // Generate TOTP secret
    const totpData = generateTOTPSecret(req.jwtUser.email);
    
    // Generate QR code data URL
    const qrCodeDataURL = await generateQRCodeDataURL(totpData.qrCode);

    // Hash backup codes for storage
    const hashedBackupCodes = await hashBackupCodes(totpData.backupCodes);

    res.json({
      message: '2FA setup initiated',
      secret: totpData.secret,
      qrCode: qrCodeDataURL,
      backupCodes: totpData.backupCodes, // Return plain codes for user to save
      instructions: {
        step1: 'Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)',
        step2: 'Enter the 6-digit code from your app to verify setup',
        step3: 'Save the backup codes in a secure location'
      }
    });
  } catch (error) {
    res.status(500).json({
      error: '2FA setup failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * POST /api/auth/2fa/verify
 * 
 * Verify TOTP token and enable 2FA for user
 * Requires authentication
 */
authRoutes.post('/2fa/verify', authenticateToken, async (req: Request, res: Response) => {
  const { secret, token } = req.body;

  if (!secret || !token) {
    return res.status(400).json({
      error: 'Missing required fields',
      message: 'secret and token are required'
    });
  }

  try {
    if (!req.jwtUser) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Valid JWT token required'
      });
    }

    // Validate TOTP token
    const isValid = validateTOTPSetup(secret, token);
    if (!isValid) {
      return res.status(400).json({
        error: 'Invalid token',
        message: 'The provided token is invalid or expired'
      });
    }

    // Get user information
    const user = await getUserById(req.jwtUser.userId);
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User associated with token no longer exists'
      });
    }

    // Update user with 2FA details (this would typically update the database)
    // For now, we'll return success - the actual database update would be implemented in the user service
    
    res.json({
      message: '2FA enabled successfully',
      twoFactorEnabled: true,
      instructions: {
        nextStep: 'Use your authenticator app to generate codes for future logins',
        backupCodesNote: 'Keep your backup codes safe - they can be used if you lose access to your authenticator app'
      }
    });
  } catch (error) {
    res.status(500).json({
      error: '2FA verification failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * POST /api/auth/2fa/authenticate
 * 
 * Verify TOTP token for 2FA-protected operations
 * Requires authentication
 */
authRoutes.post('/2fa/authenticate', authenticateToken, async (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({
      error: 'Missing token',
      message: 'TOTP token is required'
    });
  }

  try {
    if (!req.jwtUser) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Valid JWT token required'
      });
    }

    // Get user information
    const user = await getUserById(req.jwtUser.userId);
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User associated with token no longer exists'
      });
    }

    // Check if 2FA is enabled
    if (!is2FAEnabled(user)) {
      return res.status(400).json({
        error: '2FA not enabled',
        message: 'Two-factor authentication is not enabled for this account'
      });
    }

    // Verify TOTP token (using user's stored secret)
    const isValid = verifyTOTPToken(user.two_factor_secret, token);
    if (!isValid) {
      return res.status(400).json({
        error: 'Invalid token',
        message: 'The provided TOTP token is invalid'
      });
    }

    res.json({
      message: '2FA authentication successful',
      verified: true
    });
  } catch (error) {
    res.status(500).json({
      error: '2FA authentication failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * POST /api/auth/2fa/backup-code
 * 
 * Authenticate using backup code
 * Requires authentication
 */
authRoutes.post('/2fa/backup-code', authenticateToken, async (req: Request, res: Response) => {
  const { backupCode } = req.body;

  if (!backupCode) {
    return res.status(400).json({
      error: 'Missing backup code',
      message: 'Backup code is required'
    });
  }

  try {
    if (!req.jwtUser) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Valid JWT token required'
      });
    }

    // Get user information
    const user = await getUserById(req.jwtUser.userId);
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User associated with token no longer exists'
      });
    }

    // Check if 2FA is enabled
    if (!is2FAEnabled(user)) {
      return res.status(400).json({
        error: '2FA not enabled',
        message: 'Two-factor authentication is not enabled for this account'
      });
    }

    // Verify backup code (this would typically query the database for user's backup codes)
    // For now, we'll return a placeholder response
    const verification = await verifyBackupCode(backupCode, []); // Empty array - would be populated from database

    if (!verification.valid) {
      return res.status(400).json({
        error: 'Invalid backup code',
        message: 'The provided backup code is invalid or has already been used'
      });
    }

    // Mark backup code as used in database (would be implemented in user service)

    res.json({
      message: 'Backup code authentication successful',
      verified: true,
      warning: 'This backup code has been used and is no longer valid. Consider regenerating backup codes if you have used multiple codes.'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Backup code authentication failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * DELETE /api/auth/2fa/disable
 * 
 * Disable 2FA for user
 * Requires authentication
 */
authRoutes.delete('/2fa/disable', authenticateToken, async (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({
      error: 'Missing token',
      message: 'TOTP token is required to disable 2FA'
    });
  }

  try {
    if (!req.jwtUser) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Valid JWT token required'
      });
    }

    // Get user information
    const user = await getUserById(req.jwtUser.userId);
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User associated with token no longer exists'
      });
    }

    // Check if 2FA is enabled
    if (!is2FAEnabled(user)) {
      return res.status(400).json({
        error: '2FA not enabled',
        message: 'Two-factor authentication is not enabled for this account'
      });
    }

    // Verify TOTP token before disabling
    const isValid = verifyTOTPToken(user.two_factor_secret, token);
    if (!isValid) {
      return res.status(400).json({
        error: 'Invalid token',
        message: 'The provided TOTP token is invalid'
      });
    }

    // Disable 2FA (would update database via user service)
    
    res.json({
      message: '2FA disabled successfully',
      twoFactorEnabled: false
    });
  } catch (error) {
    res.status(500).json({
      error: '2FA disable failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});
