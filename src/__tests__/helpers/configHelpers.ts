/**
 * Configuration helpers for auth-providers tests
 * Loads test configuration from test-config.yaml
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';

let cachedConfig: any = null;

export interface TestConfig {
  destination?: string;
  destination_dir?: string; // Base directory for service-keys and sessions subdirectories
  service_key_path?: string; // Relative path to specific service key file (alternative to destination_dir)
  session_path?: string; // Any session file: absolute, ~/..., or relative to the project root
  interactive_login?: boolean; // Allow tests that open a browser (default: false)
}

/** What resolveSessionFile needs, passed in so every platform can be tested anywhere. */
export interface SessionFileInputs {
  env: Record<string, string | undefined>;
  config: TestConfig;
  platform: NodeJS.Platform;
  homeDir: string;
  projectRoot: string;
}

/**
 * The session file the live tests read. First rule that applies wins:
 * MCP_ABAP_ADT_SESSION_FILE, then `session_path`, then the folder the stores
 * use — <destination_dir>/sessions/<destination>.env, where destination_dir
 * defaults to ~/.config/mcp-abap-adt (Unix) or <home>/Documents/mcp-abap-adt
 * (Windows). Any file works; it need not be named after the destination.
 */
export function resolveSessionFile(inputs: SessionFileInputs): string | null {
  const { env, config, platform, homeDir, projectRoot } = inputs;
  const p = platform === 'win32' ? path.win32 : path.posix;
  const expand = (value: string): string =>
    value === '~' || value.startsWith('~/') || value.startsWith('~\\')
      ? p.join(homeDir, value.slice(1))
      : value;
  const explicit = (value: string): string => {
    const expanded = expand(value);
    return p.isAbsolute(expanded) ? expanded : p.resolve(projectRoot, expanded);
  };

  const fromEnv = env.MCP_ABAP_ADT_SESSION_FILE;
  if (fromEnv) return explicit(fromEnv);
  if (config.session_path) return explicit(config.session_path);
  if (!config.destination) return null;

  const base = config.destination_dir
    ? expand(config.destination_dir)
    : platform === 'win32'
      ? p.join(homeDir, 'Documents', 'mcp-abap-adt')
      : p.join(homeDir, '.config', 'mcp-abap-adt');
  return p.join(base, 'sessions', `${config.destination}.env`);
}

/**
 * Whether a test may open a browser for a person to log in. Off unless the
 * config says `interactive_login: true` or MCP_ABAP_ADT_INTERACTIVE=1 is set:
 * a default run must never wait for a human.
 */
export function interactiveLoginEnabled(inputs: {
  env: Record<string, string | undefined>;
  config: TestConfig;
}): boolean {
  return (
    inputs.config.interactive_login === true ||
    inputs.env.MCP_ABAP_ADT_INTERACTIVE === '1'
  );
}

/**
 * Find project root directory by looking for package.json
 */
function findProjectRoot(): string {
  let currentDir = __dirname;
  while (currentDir !== path.dirname(currentDir)) {
    const packageJsonPath = path.join(currentDir, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      return currentDir;
    }
    currentDir = path.dirname(currentDir);
  }
  // Fallback to process.cwd() if package.json not found
  return process.cwd();
}

/**
 * Load test configuration from YAML
 * Uses test-config.yaml from tests/ directory
 */
export function loadTestConfig(): TestConfig {
  if (cachedConfig) {
    return cachedConfig;
  }

  // Find project root and load from tests/test-config.yaml
  const projectRoot = findProjectRoot();
  const configPath = path.resolve(projectRoot, 'tests', 'test-config.yaml');
  const templatePath = path.resolve(
    projectRoot,
    'tests',
    'test-config.yaml.template',
  );

  if (process.env.TEST_VERBOSE) {
    console.log(`[configHelpers] Project root: ${projectRoot}`);
    console.log(`[configHelpers] Config path: ${configPath}`);
    console.log(`[configHelpers] Config exists: ${fs.existsSync(configPath)}`);
  }

  if (fs.existsSync(configPath)) {
    try {
      const configContent = fs.readFileSync(configPath, 'utf8');
      cachedConfig = (yaml.load(configContent) as TestConfig) || {};
      if (process.env.TEST_VERBOSE) {
        console.log(
          `[configHelpers] Loaded config:`,
          JSON.stringify(cachedConfig, null, 2),
        );
      }
      return cachedConfig;
    } catch (error) {
      console.warn(`Failed to load test config from ${configPath}:`, error);
      return {};
    }
  }

  if (fs.existsSync(templatePath)) {
    console.warn(
      '⚠️  tests/test-config.yaml not found. Using template (all integration tests will be disabled).',
    );
    try {
      const templateContent = fs.readFileSync(templatePath, 'utf8');
      cachedConfig = (yaml.load(templateContent) as TestConfig) || {};
      return cachedConfig;
    } catch (error) {
      console.warn(
        `Failed to load test config template from ${templatePath}:`,
        error,
      );
      return {};
    }
  }

  console.warn('⚠️  Test configuration files not found.');
  console.warn('Please create tests/test-config.yaml with test parameters.');
  return {};
}

/**
 * Check if test config has real values (not placeholders)
 */
export function hasRealConfigValue(config?: TestConfig): boolean {
  const cfg = config || loadTestConfig();
  if (!cfg.destination) {
    return false;
  }
  // Check if destination is not a placeholder
  return !cfg.destination.includes('<') && !cfg.destination.includes('>');
}

/**
 * Get destination from config
 */
export function getDestination(config?: TestConfig): string | null {
  const cfg = config || loadTestConfig();
  return cfg.destination || null;
}

/**
 * Get default destination directory based on platform
 */
function getDefaultDestinationDir(): string {
  const homeDir = process.env.HOME || process.env.USERPROFILE || '';
  if (process.platform === 'win32') {
    return path.join(homeDir, 'Documents', 'mcp-abap-adt');
  }
  return path.join(homeDir, '.config', 'mcp-abap-adt');
}

/**
 * Get destination directory from config or use default
 */
function getDestinationDir(config?: TestConfig): string {
  const cfg = config || loadTestConfig();

  if (cfg.destination_dir) {
    // Expand ~ to home directory
    if (cfg.destination_dir.startsWith('~')) {
      const homeDir = process.env.HOME || process.env.USERPROFILE || '';
      return cfg.destination_dir.replace('~', homeDir);
    }
    return cfg.destination_dir;
  }

  return getDefaultDestinationDir();
}

/**
 * Get service keys directory from config
 * Uses base_dir/service-keys or default platform path
 */
export function getServiceKeysDir(config?: TestConfig): string {
  const cfg = config || loadTestConfig();

  // If service_key_path is specified, return its directory
  if (cfg.service_key_path) {
    const projectRoot = findProjectRoot();
    const fullPath = path.resolve(projectRoot, cfg.service_key_path);
    return path.dirname(fullPath);
  }

  // Use destination_dir/service-keys
  const destinationDir = getDestinationDir(cfg);
  return path.join(destinationDir, 'service-keys');
}

/**
 * Get sessions directory from config
 * Uses base_dir/sessions or default platform path
 */
export function getSessionsDir(config?: TestConfig): string {
  const cfg = config || loadTestConfig();

  // If session_path is specified, return its directory
  if (cfg.session_path) {
    const projectRoot = findProjectRoot();
    const fullPath = path.resolve(projectRoot, cfg.session_path);
    return path.dirname(fullPath);
  }

  // Use destination_dir/sessions
  const destinationDir = getDestinationDir(cfg);
  return path.join(destinationDir, 'sessions');
}

/**
 * Get service key file path
 * Returns full path to service key file
 */
export function getServiceKeyPath(config?: TestConfig): string | null {
  const cfg = config || loadTestConfig();
  const destination = cfg.destination;
  if (!destination) return null;

  // If service_key_path is specified, use it
  if (cfg.service_key_path) {
    const projectRoot = findProjectRoot();
    return path.resolve(projectRoot, cfg.service_key_path);
  }

  // Construct from directory + destination
  const serviceKeysDir = getServiceKeysDir(cfg);
  return path.join(serviceKeysDir, `${destination}.json`);
}

/**
 * Get session file path
 * Returns full path to session file
 */
export function getSessionPath(config?: TestConfig): string | null {
  return resolveSessionFile({
    env: process.env,
    config: config || loadTestConfig(),
    platform: process.platform,
    homeDir: process.env.HOME || process.env.USERPROFILE || '',
    projectRoot: findProjectRoot(),
  });
}

// Legacy functions for backward compatibility
export function getAbapDestination(config?: TestConfig): string | null {
  return getDestination(config);
}

export function hasRealConfig(
  config?: TestConfig,
  _section?: 'abap' | 'xsuaa',
): boolean {
  return hasRealConfigValue(config);
}
