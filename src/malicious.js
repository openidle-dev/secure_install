import { getCached, setCached } from './cache.js';

let KNOWN_MALICIOUS = null;
let SUSPICIOUS_DATA = null;

async function getSuspiciousPatterns() {
  if (SUSPICIOUS_DATA) return SUSPICIOUS_DATA;
  
  const cacheKey = 'security:patterns';
  const cached = getCached(cacheKey);
  if (cached) {
    SUSPICIOUS_DATA = cached;
    return SUSPICIOUS_DATA;
  }
  
  try {
    const response = await fetch('https://registry.npmjs.org/-/v1/security/advisories');
    if (response && response.ok) {
      const patterns = {
        prefixes: ['skynet-', 'env-', 'sys-', 'proc-', 'win-', 'mac-', 'linux-']
      };
      setCached(cacheKey, patterns);
      SUSPICIOUS_DATA = patterns;
      return patterns;
    }
  } catch {}
  
  const fallback = {
    prefixes: ['skynet-', 'env-', 'sys-', 'proc-']
  };
  SUSPICIOUS_DATA = fallback;
  return fallback;
}

async function fetchMaliciousPackages() {
  if (KNOWN_MALICIOUS) return KNOWN_MALICIOUS;
  
  const cacheKey = 'malware:list';
  const cached = getCached(cacheKey);
  if (cached) {
    KNOWN_MALICIOUS = new Set(cached);
    return KNOWN_MALICIOUS;
  }
  
  try {
    const response = await fetch('https://registry.npmjs.org/-/v1/security/advisories');
    if (response && response.ok) {
      const data = await response.json();
      const malicious = new Set();
      
      if (data.objects) {
        for (const obj of data.objects) {
          if (obj.advisory && obj.advisory.vulnerable_version_range) {
            const packages = Object.keys(obj.advisory.vulnerable_versions || {});
            packages.forEach(p => malicious.add(p.toLowerCase()));
          }
        }
      }
      
      if (malicious.size > 0) {
        KNOWN_MALICIOUS = malicious;
        setCached(cacheKey, [...malicious]);
        return KNOWN_MALICIOUS;
      }
    }
  } catch {}
  
  KNOWN_MALICIOUS = new Set();
  return KNOWN_MALICIOUS;
}

export async function isKnownMalicious(packageName) {
  const malicious = await fetchMaliciousPackages();
  return malicious.has(packageName.toLowerCase());
}

export async function isSuspiciousPattern(packageName) {
  const patterns = await getSuspiciousPatterns();
  const lower = packageName.toLowerCase();
  
  for (const prefix of patterns.prefixes) {
    if (lower.startsWith(prefix) && lower.length > prefix.length + 3) {
      return true;
    }
  }
  
  return false;
}

export async function checkMaliciousPackage(packageName) {
  const cacheKey = `malware:${packageName}`;
  const cached = getCached(cacheKey);
  if (cached !== null) return cached;
  
  if (await isKnownMalicious(packageName)) {
    setCached(cacheKey, true);
    return true;
  }
  
  if (await isSuspiciousPattern(packageName)) {
    setCached(cacheKey, true);
    return true;
  }
  
  try {
    const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`);
    if (!response || !response.ok) {
      setCached(cacheKey, false);
      return false;
    }
    
    const data = await response.json();
    const time = data.time;
    
    if (time && time.created) {
      const createdDate = new Date(time.created);
      const ageInHours = (Date.now() - createdDate.getTime()) / (1000 * 60 * 60);
      
      if (ageInHours < 1 && (!data.maintainers || data.maintainers.length === 0)) {
        setCached(cacheKey, true);
        return true;
      }
    }
    
    setCached(cacheKey, false);
    return false;
  } catch {
    setCached(cacheKey, false);
    return false;
  }
}

export function checkDependencyConfusion(pkgName) {
  if (pkgName.includes(':')) {
    const [protocol] = pkgName.split(':');
    if (protocol !== 'file' && protocol !== 'git' && protocol !== 'npm') {
      return `Suspicious protocol in package name: ${protocol}`;
    }
  }
  return null;
}