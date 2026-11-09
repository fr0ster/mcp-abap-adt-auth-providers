// The tests moved to node:test are the files tsconfig.test.json compiles by name
// (`files`); Jest leaves them alone. The list lives there only, and the ignores live
// here only: a `--testPathIgnorePatterns` flag would replace them, and the default.
const { files: moved = [] } = require('./tsconfig.test.json');
// A pattern per file. Jest turns its `/` into the platform's separator, as it does for
// its own '/node_modules/'.
const ignored = (file) => `<rootDir>/${file.replaceAll('.', '\\.')}$`;

module.exports = {
  testPathIgnorePatterns: ['/node_modules/', ...moved.map(ignored)],
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: { esModuleInterop: true } }],
  },
  verbose: true,
  maxWorkers: 1,
};
