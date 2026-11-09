// Removes the paths given, as `rm -rf` would, on every platform the package supports:
// a missing path is no error. Used by `clean` and `test:build` instead of a shell command.
import { rmSync } from 'node:fs';

for (const path of process.argv.slice(2)) {
  rmSync(path, { recursive: true, force: true });
}
