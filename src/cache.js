import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const CACHE_DIR = join(homedir(), '.secure-install');
const CACHE_FILE = join(CACHE_DIR, 'cache.json');
const MAX_CACHE_SIZE = 5 * 1024 * 1024;

function ensureCacheDir() {
  try {
    if (!existsSync(CACHE_DIR)) {
      mkdirSync(CACHE_DIR, { mode: 0o700, recursive: true });
    }
  } catch {}
}

function loadCache() {
  try {
    ensureCacheDir();
    if (existsSync(CACHE_FILE)) {
      const stats = statSync(CACHE_FILE);
      if (stats.size > MAX_CACHE_SIZE) {
        return {};
      }
      const data = JSON.parse(readFileSync(CACHE_FILE, 'utf-8'));
      if (data && typeof data === 'object' && data.cache) {
        return data.cache;
      }
    }
  } catch {}
  return {};
}

function saveCache(cache) {
  try {
    ensureCacheDir();
    const json = JSON.stringify({ cache, timestamp: Date.now() });
    if (json.length > MAX_CACHE_SIZE) {
      const keys = Object.keys(cache);
      const toRemove = Math.floor(keys.length * 0.5);
      for (let i = 0; i < toRemove; i++) {
        delete cache[keys[i]];
      }
    }
    writeFileSync(CACHE_FILE, json, { mode: 0o600 });
  } catch {}
}

const cache = loadCache();
const TTL = 1000 * 60 * 15;

export function getCached(key) {
  if (!key || typeof key !== 'string' || key.length > 200) return null;
  const entry = cache[key];
  if (entry && Date.now() - entry.ts < TTL) {
    return entry.data;
  }
  return null;
}

export function setCached(key, data) {
  if (!key || typeof key !== 'string' || key.length > 200) return;
  if (data && typeof data === 'object') {
    cache[key] = { ts: Date.now(), data };
    saveCache(cache);
  }
}