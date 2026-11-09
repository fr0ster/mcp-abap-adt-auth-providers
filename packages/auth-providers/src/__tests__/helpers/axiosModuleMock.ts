/**
 * axios replaced by a mock for the whole test file (`mock.module`, under the
 * runner's `--experimental-test-module-mocks`): what was `jest.mock('axios')`.
 *
 * Import it for its effect FIRST, before any module under test:
 *
 *     import '../helpers/axiosModuleMock';
 *     …
 *     import { mockedAxios, resetAxiosMock } from '../helpers/axiosModuleMock';
 *
 * The production sites bind axios when their module loads (`axios_1 =
 * __importDefault(require('axios'))`); a module loaded before this one keeps
 * the real axios (`mocking/axiosPin.test.ts` pins both).
 *
 * `mockedAxios` is what every site calls: itself for `axios(config)`, its
 * `post` and `get` for those. Each answers `undefined` until a test gives it
 * an implementation, as Jest's automock did. `AxiosError` and
 * `isAxiosError` are axios's own: no site calls them (Code: src reads only
 * `axios(…)`, `axios.post`, `axios.get`).
 */

import { mock } from 'node:test';
import type { AxiosRequestConfig } from 'axios';
import { clearMock, resetMock } from './mockOnce';

// The real module, read once before the mock is in place: its error class.
import realAxios = require('axios');

/** `axios(config)`. */
const request = mock.fn<(config: AxiosRequestConfig) => Promise<unknown>>();
/** `axios.post(url, data, config)`. */
const post =
  mock.fn<
    (
      url: string,
      data?: unknown,
      config?: AxiosRequestConfig,
    ) => Promise<unknown>
  >();
/** `axios.get(url, config)`. */
const get =
  mock.fn<(url: string, config?: AxiosRequestConfig) => Promise<unknown>>();

export const mockedAxios = Object.assign(request, {
  post,
  get,
  // axios's own: no site reads them, the tests build and check errors with them.
  AxiosError: realAxios.AxiosError,
  isAxiosError: realAxios.isAxiosError,
});

/**
 * The same call on every supported line, with no deprecated option: Node 24
 * and later take `exports` (`default` is what `require` answers); Node 22
 * has no `exports` and takes `defaultExport`, not deprecated there. Which one
 * applies is read from what `require('axios')` answers, not from a version.
 */
// By its resolved path: the bare name `axios` is not matched to what the
// sites require (measured on Node 26: the real module came back).
const AXIOS = require.resolve('axios');
const viaExports = mock.module(AXIOS, { exports: { default: mockedAxios } });
if (require('axios') !== mockedAxios) {
  viaExports.restore();
  mock.module(AXIOS, { defaultExport: mockedAxios });
}
if (require('axios') !== mockedAxios) {
  throw new Error('axiosModuleMock: mock.module did not replace axios');
}

/** Every call forgotten and every implementation given back: Jest's `resetAllMocks` for axios. */
export function resetAxiosMock(): void {
  resetMock(request);
  resetMock(post);
  resetMock(get);
}

/** Every call forgotten, the implementations kept: Jest's `clearAllMocks` for axios. */
export function clearAxiosMockCalls(): void {
  clearMock(request);
  clearMock(post);
  clearMock(get);
}
