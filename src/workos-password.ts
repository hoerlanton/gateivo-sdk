import express, {type Router} from 'express';
import type {AppAction} from './types.js';
import type {ResolveLoginAccount} from './login-contract.js';
import {createPasswordLogin, type PasswordLoginOptions} from './login-express.js';
import {createLoginPostgresStore, type LoginPostgresPool} from './login-postgres.js';
import {createWorkOSStandaloneLogin} from './workos-standalone.js';
import {createWorkOSConnection, type WorkOSConnection, type WorkOSConnectionBaseOptions,
  type WorkOSConnectionDependencies} from './workos-connect-express.js';
import {createWorkOSPostgresStore} from './workos-connect-postgres.js';

export interface WorkOSPasswordConnectionOptions extends Omit<WorkOSConnectionBaseOptions,
  'store' | 'authenticateSession' | 'resolveAccount' | 'resolveTokenSubject'> {
  pool: LoginPostgresPool;
  /** Two private schemas are created only by explicit migrate(): <prefix>_login and <prefix>_consent. */
  schemaPrefix: string;
  actions: AppAction[];
  verifyCredentials: PasswordLoginOptions['verifyCredentials'];
  resolveLoginAccount: ResolveLoginAccount;
  accountName?: string;
}
export interface WorkOSPasswordConnection {
  readonly router: Router;
  readonly registry: WorkOSConnection['registry'];
  /** Explicit deployment task. Never run automatically during startup or HTTP requests. */
  migrate(): Promise<void>;
  ready(): Promise<void>;
  /** Stops SDK work; the application keeps ownership of its pool. */
  close(): Promise<void>;
}

/** Optional password-based application adapter; publisher verification remains authoritative. */
export function createWorkOSPasswordConnection(options: WorkOSPasswordConnectionOptions,
  dependencies: WorkOSConnectionDependencies = {}): WorkOSPasswordConnection {
  if (!options || typeof options.verifyCredentials !== 'function' || typeof options.resolveLoginAccount !== 'function'
    || typeof options.schemaPrefix !== 'string' || !/^[a-z][a-z0-9_]{0,49}$/.test(options.schemaPrefix) || options.schemaPrefix.startsWith('pg_')) {
    throw new TypeError('Configure publisher authentication and a private schema prefix.');
  }
  const {pool, schemaPrefix, verifyCredentials, resolveLoginAccount, accountName, ...common} = options;
  const loginStore = createLoginPostgresStore({pool, appId: common.appId, schema: schemaPrefix + '_login'});
  const consentStore = createWorkOSPostgresStore({pool, schema: schemaPrefix + '_consent'});
  const login = createPasswordLogin({appId: common.appId, publicUrl: common.publicUrl, secret: common.secret,
    store: loginStore, verifyCredentials, resolveAccount: resolveLoginAccount, accountName,
    trustProxyHttps: common.trustProxyHttps, accessExpiresAt: common.accessExpiresAt});
  try {
    const standalone = createWorkOSStandaloneLogin({appId: common.appId, publicUrl: common.publicUrl,
      issuer: common.issuer, clientId: common.clientId, apiKey: common.apiKey, secret: common.secret,
      store: loginStore, authenticateSession: login.authenticateSession, resolveLoginAccount,
      trustProxyHttps: common.trustProxyHttps, accessExpiresAt: common.accessExpiresAt}, dependencies);
    const connection = createWorkOSConnection({...common, mountMcp: true, store: consentStore,
      authenticateSession: login.authenticateSession, resolveAccount: standalone.resolveAccount,
      resolveTokenSubject: standalone.resolveTokenSubject}, dependencies);
    const router = express.Router();
    router.use(login.router, standalone.router, connection.router);
    return Object.freeze({router, registry: connection.registry,
      async migrate() {await loginStore.migrate(); await consentStore.migrate();},
      async ready() {await Promise.all([loginStore.checkReady(), consentStore.checkReady()]);},
      async close() {await login.close(); await Promise.all([loginStore.close(), consentStore.close()]);},
    });
  } catch (error) {
    void login.close(); void loginStore.close(); void consentStore.close();
    throw error;
  }
}
