/**
 * Test logger with environment variable control
 */

import type { ILogger } from '@mcp-abap-adt/interfaces';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

function getLogLevel(): LogLevel {
  const level = process.env.LOG_LEVEL?.toLowerCase() || 'info';
  const levels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
  return levels.includes(level as LogLevel) ? (level as LogLevel) : 'info';
}

function shouldLog(level: LogLevel): boolean {
  const currentLevel = getLogLevel();
  const levels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
  return levels.indexOf(level) >= levels.indexOf(currentLevel);
}

export function createTestLogger(prefix: string = 'TEST'): ILogger {
  const level = getLogLevel();
  const enabled =
    process.env.DEBUG_AUTH_PROVIDERS === 'true' ||
    process.env.DEBUG_BROWSER_AUTH === 'true' ||
    process.env.DEBUG === 'true';

  return {
    debug: (message: string, meta?: any) => {
      if (enabled && shouldLog('debug')) {
        console.debug(`[${prefix}] [DEBUG] ${message}`, meta || '');
      }
    },
    info: (message: string, meta?: any) => {
      if (enabled && shouldLog('info')) {
        console.info(`[${prefix}] ${message}`, meta || '');
      }
    },
    warn: (message: string, meta?: any) => {
      if (enabled && shouldLog('warn')) {
        console.warn(`[${prefix}] [WARN] ${message}`, meta || '');
      }
    },
    error: (message: string, meta?: any) => {
      if (enabled && shouldLog('error')) {
        console.error(`[${prefix}] [ERROR] ${message}`, meta || '');
      }
    },
  };
}
