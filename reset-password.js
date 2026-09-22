// Emergency password reset — run this directly on the server when
// someone (including the only admin) is completely locked out and has
// no recovery question set. Requires file access to the server, so it
// can't be triggered remotely or from the browser.
//
// Usage:
//   node reset-password.js <username> <newPassword>
//
// Example:
//   node reset-password.js admin MyNewPassword123

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const USERS_FILE = path.join(__dirname, 'users.json');

function makeSalt() { return crypto.randomBytes(16).toString('hex'); }
function hashPassword(password, salt) { return crypto.scryptSync(String(password), salt, 64).toString('hex'); }

const [, , username, newPassword] = process.argv;

if (!username || !newPassword) {
  console.error('Usage: node reset-password.js <username> <newPassword>');
  process.exit(1);
}
if (newPassword.length < 4) {
  console.error('New password must be at least 4 characters.');
  process.exit(1);
}
if (!fs.existsSync(USERS_FILE)) {
  console.error(`Could not find ${USERS_FILE}. Run this from the project folder.`);
  process.exit(1);
}

const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
const user = users.find((u) => u.username.toLowerCase() === username.toLowerCase());

if (!user) {
  console.error(`No user named "${username}" was found in users.json.`);
  console.error('Existing usernames: ' + users.map((u) => u.username).join(', '));
  process.exit(1);
}

user.salt = makeSalt();
user.passwordHash = hashPassword(newPassword, user.salt);
// Clear any recovery-question data too, since the person resetting it
// this way clearly can't answer it right now.
delete user.securityQuestion;
delete user.securityAnswerHash;
delete user.securityAnswerSalt;

fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
console.log(`Password for "${user.username}" has been reset.`);
console.log('You can log in with the new password right away — no server restart needed.');
console.log('Consider setting a recovery question for this account under Settings once you are back in.');
