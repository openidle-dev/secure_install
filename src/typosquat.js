import levenshtein from 'fast-levenshtein';
import { getCached, setCached } from './cache.js';

let POPULAR_PACKAGES = null;

async function fetchPopularPackages() {
  if (POPULAR_PACKAGES) return POPULAR_PACKAGES;
  
  const cached = getCached('popular:packages');
  if (cached) {
    POPULAR_PACKAGES = cached;
    return POPULAR_PACKAGES;
  }
  
  try {
    const response = await fetch('https://registry.npmjs.org/-/v1/search?text=popularity&size=100');
    const data = await response.json();
    POPULAR_PACKAGES = data.objects.map(pkg => pkg.package.name);
    setCached('popular:packages', POPULAR_PACKAGES);
    return POPULAR_PACKAGES;
  } catch {
    return ['react', 'express', 'lodash', 'chalk', 'jest', 'typescript', 'axios'];
  }
}

export async function checkTyposquatting(packageName) {
  const popularPackages = await fetchPopularPackages();
  
  if (popularPackages.includes(packageName)) {
    return null; 
  }

  for (const popular of popularPackages) {
    const distance = levenshtein.get(packageName, popular);
    if (distance === 1 || (distance === 2 && packageName.length > 6)) {
      return `Potential typosquatting of highly popular package: '${popular}'`;
    }
  }

  return null;
}
