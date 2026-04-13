import { getCached, setCached } from './cache.js';

async function fetchWithRetry(url, options = {}, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, options);
      if (response.ok) return response;
    } catch {}
    if (i < retries - 1) await new Promise(r => setTimeout(r, 500));
  }
  return null;
}

export async function checkVulnerabilities(packageName, version) {
  const cacheKey = `vuln:${packageName}@${version}`;
  const cached = getCached(cacheKey);
  if (cached !== null) return cached;
  
  const url = 'https://api.osv.dev/v1/query';
  
  const payload = {
    package: {
      name: packageName,
      ecosystem: 'npm'
    },
    version: version
  };

  try {
    const response = await fetchWithRetry(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response) {
      setCached(cacheKey, null);
      return null;
    }

    const data = await response.json();
    const vulns = data.vulns || [];
    setCached(cacheKey, vulns);
    return vulns;
  } catch {
    setCached(cacheKey, null);
    return null;
  }
}
