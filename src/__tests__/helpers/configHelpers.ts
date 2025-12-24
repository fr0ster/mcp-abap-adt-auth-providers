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
  session_path?: string; // Relative path to specific session file (alternative to destination_dir)
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
  const cfg = config || loadTestConfig();
  const destination = cfg.destination;
  if (!destination) return null;

  // If session_path is specified, use it
  if (cfg.session_path) {
    const projectRoot = findProjectRoot();
    return path.resolve(projectRoot, cfg.session_path);
  }

  // Construct from directory + destination
  const sessionsDir = getSessionsDir(cfg);
  return path.join(sessionsDir, `${destination}.env`);
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
