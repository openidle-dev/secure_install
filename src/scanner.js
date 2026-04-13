import { getCached, setCached } from './cache.js';

let requestQueue = [];
let isProcessing = false;
const RATE_LIMIT_DELAY = 100;

async function rateLimitedFetch(url, options = {}, retries = 3) {
  return new Promise((resolve) => {
    const attempt = async () => {
      for (let i = 0; i < retries; i++) {
        try {
          const response = await fetch(url, options);
          if (response.ok) {
            resolve(response);
            return;
          }
          if (response.status === 404) {
            resolve(null);
            return;
          }
          if (response.status === 429) {
            await new Promise(r => setTimeout(r, 1000 * (i + 1)));
            continue;
          }
        } catch {}
        if (i < retries - 1) await new Promise(r => setTimeout(r, 500));
      }
      resolve(null);
    };
    
    requestQueue.push(attempt);
    processQueue();
  });
}

async function processQueue() {
  if (isProcessing || requestQueue.length === 0) return;
  isProcessing = true;
  
  while (requestQueue.length > 0) {
    const fn = requestQueue.shift();
    await fn();
    await new Promise(r => setTimeout(r, RATE_LIMIT_DELAY));
  }
  
  isProcessing = false;
}

export async function fetchPackageMetadata(packageName) {
  let pkgName = packageName;
  
  if (packageName.startsWith('@')) {
    const atIndex = packageName.indexOf('@', 1);
    if (atIndex > 1) {
      pkgName = packageName.slice(0, atIndex);
    }
  } else {
    const atIndex = packageName.lastIndexOf('@');
    if (atIndex > 0) {
      pkgName = packageName.slice(0, atIndex);
    }
  }
  
  const cacheKey = `pkg:${pkgName}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;
  
  const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`;
  const response = await rateLimitedFetch(url);
  if (!response) {
    throw new Error(`Failed to fetch metadata for ${pkgName}`);
  }
  const data = await response.json();
  setCached(cacheKey, data);
  return data;
}

export function getLatestVersionData(metadata) {
  const latestVersion = metadata['dist-tags']?.latest;
  if (!latestVersion) {
     throw new Error('Could not determine latest version.');
  }
  return metadata.versions[latestVersion];
}
