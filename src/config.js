import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { cwd } from 'process';

export function loadConfig() {
  const configPaths = [
    join(cwd(), '.secure-install.json'),
    join(cwd(), 'secure-install.config.json'),
    join(cwd(), '.config', 'secure-install.json'),
    join(process.env.HOME || '', '.secure-install.json')
  ];
  
  for (const path of configPaths) {
    if (existsSync(path)) {
      try {
        const data = JSON.parse(readFileSync(path, 'utf-8'));
        return data;
      } catch {}
    }
  }
  
  return {};
}

export function getConfigValue(key, defaultValue) {
  const config = loadConfig();
  return config[key] ?? defaultValue;
}