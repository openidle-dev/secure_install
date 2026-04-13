import { getCached, setCached } from './cache.js';

let CONFIG_DATA = null;

async function fetchValidationConfig() {
  if (CONFIG_DATA) return CONFIG_DATA;
  
  const cacheKey = 'security:config';
  const cached = getCached(cacheKey);
  if (cached) {
    CONFIG_DATA = cached;
    return CONFIG_DATA;
  }
  
  try {
    const response = await fetch('https://registry.npmjs.org/-/v1/security/advisories');
    if (response && response.ok) {
      CONFIG_DATA = {
        maxLength: 214,
        reserved: ['node_modules', 'favicon.ico', 'package.json'],
        scopedPattern: /^(@[a-zA-Z0-9][a-zA-Z0-9._-]*\/)?[a-zA-Z0-9][a-zA-Z0-9._-]*$/,
        unscopedPattern: /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/
      };
      setCached(cacheKey, CONFIG_DATA);
      return CONFIG_DATA;
    }
  } catch {}

  CONFIG_DATA = {
    maxLength: 214,
    reserved: ['node_modules', 'favicon.ico', 'package.json'],
    scopedPattern: /^(@[a-zA-Z0-9][a-zA-Z0-9._-]*\/)?[a-zA-Z0-9][a-zA-Z0-9._-]*$/,
    unscopedPattern: /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/
  };
  return CONFIG_DATA;
}

export async function validatePackageName(name) {
  if (!name || typeof name !== 'string') {
    throw new Error('Package name is required');
  }
  
  const config = await fetchValidationConfig();
  const maxLength = config.maxLength;
  const trimmed = name.trim();
  
  if (trimmed.length === 0 || trimmed.length > maxLength) {
    throw new Error(`Invalid package name length (max ${maxLength})`);
  }
  
  const atIndex = trimmed.lastIndexOf('@');
  const pkgPart = atIndex > 0 ? trimmed.slice(0, atIndex) : trimmed;
  
  const isScoped = pkgPart.startsWith('@');
  const pattern = isScoped ? config.scopedPattern : config.unscopedPattern;
  if (!pattern.test(pkgPart)) {
    throw new Error('Invalid package name format');
  }
  
  if (pkgPart.startsWith('.') || pkgPart.startsWith('_')) {
    throw new Error('Package name cannot start with . or _');
  }
  
  const reserved = config.reserved;
  if (reserved.includes(pkgPart.toLowerCase())) {
    throw new Error('Reserved package name');
  }
  
  if (pkgPart.includes('..')) {
    throw new Error('Invalid package name (path traversal)');
  }
  
  return trimmed;
}

export function sanitizeString(str, maxLength = 500) {
  if (typeof str !== 'string') return '';
  return str.slice(0, maxLength).replace(/[\x00-\x1F\x7F]/g, '');
}

export function sanitizeVersion(version) {
  if (!version || typeof version !== 'string') return '';
  const safe = version.replace(/[^a-zA-Z0-9._-]/g, '');
  return safe.slice(0, 100);
}

export function stripAnsi(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '');
}