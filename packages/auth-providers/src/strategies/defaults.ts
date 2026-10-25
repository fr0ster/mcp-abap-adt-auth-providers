/**
 * Today's values: the parts have no
 * default port, browser or redirect; the named compositions are the only
 * place these live.
 */

/**
 * Above Linux's `ip_local_port_range` (32768–60999), so an outbound connection
 * never squats on it, and far from the 3001/3333 range application servers use.
 */
export const DEFAULT_CALLBACK_PORT = 61001;

/** The endpoint path every named composition's redirect arrives at. */
export const CALLBACK_ENDPOINT = '/callback';
