import type { PasswordLogin, PasswordLoginOptions } from './login-express.js';

/** Internal runtime boundary. */
export function createPasswordLoginRuntime(options: PasswordLoginOptions): PasswordLogin;
