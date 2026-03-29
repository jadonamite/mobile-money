-- Migration: 20260329_add_user_role
-- Description: Add role column to users table for access control
-- Up migration

-- 1. Add column with correct default
ALTER TABLE users
ADD COLUMN IF NOT EXISTS role_id UUID;

ALTER TABLE users
ALTER COLUMN role_id SET NOT NULL;

-- 2. Normalize: Before adding the constraint, make sure all existing users.role values exist in roles.name.
-- UPDATE users
-- SET role = 'users'
-- WHERE role iS NULL 
--     OR role IN (SELECT name FROM roles);

-- 3. Add index
CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);

-- 4. Add the foreign key constraint to users
ALTER TABLE users 
ADD CONSTRAINT user_role_fkey
FOREIGN KEY (role_id)
REFERENCES roles(id)
ON UPDATE CASCADE
ON DELETE RESTRICT;
