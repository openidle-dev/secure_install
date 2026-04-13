import { getCached, setCached } from './cache.js';

export async function checkLicense(packageName) {
  const cacheKey = `license:${packageName}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;
  
  try {
    const response = await fetch(`https://registry.npmjs.org/${packageName}/latest`);
    if (!response.ok) return null;
    const data = await response.json();
    const license = data.license || 'Unknown';
    setCached(cacheKey, license);
    return license;
  } catch {
    return null;
  }
}

export async function checkRepository(pkgVersionData) {
  const repo = pkgVersionData.repository;
  if (!repo) return null;
  
  const url = typeof repo === 'string' ? repo : repo.url;
  if (!url) return null;
  
  let parsedUrl = url;
  if (url.startsWith('git+')) parsedUrl = url.slice(4);
  if (url.endsWith('.git')) parsedUrl = url.slice(0, -4);
  
  const isValid = parsedUrl.includes('github.com') || 
                  parsedUrl.includes('gitlab.com') || 
                  parsedUrl.includes('bitbucket.org');
  
  return isValid ? parsedUrl : null;
}