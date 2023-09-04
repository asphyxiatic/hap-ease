import { execSync } from 'child_process';

const [, , name] = process.argv;

execSync(
  `yarn build && yarn typeorm migration:generate -d ./dist/src/database/index.js ./src/database/migrations/${name}`,
  { stdio: 'inherit' },
);
