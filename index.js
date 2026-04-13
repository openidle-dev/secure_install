export { fetchPackageMetadata, getLatestVersionData } from './src/scanner.js';
export { calculateRisk } from './src/risk.js';
export { checkScripts } from './src/scripts-check.js';
export { installPackage } from './src/install.js';
export { checkLicense, checkRepository } from './src/license.js';
export { checkMaliciousPackage, isKnownMalicious, isSuspiciousPattern } from './src/malicious.js';
export { getCached, setCached } from './src/cache.js';
export { validatePackageName, sanitizeString } from './src/security.js';
export { loadConfig, getConfigValue } from './src/config.js';