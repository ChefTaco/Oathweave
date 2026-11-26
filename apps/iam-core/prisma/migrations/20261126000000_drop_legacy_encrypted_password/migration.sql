-- Passwords are one-way credentials. The reversible escrow column has been NULL since
-- 20260709000000_remove_password_escrow and every write keeps it NULL; drop it.
ALTER TABLE "users" DROP COLUMN "encryptedPassword";
