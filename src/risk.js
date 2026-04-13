import { checkScripts } from './scripts-check.js';
import { checkVulnerabilities } from './osv.js';
import { checkTyposquatting } from './typosquat.js';
import { fetchPackageMetadata } from './scanner.js';
import { checkLicense, checkRepository } from './license.js';
import { isKnownMalicious, isSuspiciousPattern, checkMaliciousPackage } from './malicious.js';

async function checkDependencyRisks(dependencies, depth = 0, skipDepScan = false) {
  if (skipDepScan || !dependencies || depth > 1) return [];
  
  const risks = [];
  const depNames = Object.keys(dependencies).slice(0, 10);
  
  const checkDep = async (depName) => {
    try {
      const meta = await fetchPackageMetadata(depName);
      const versionData = meta.versions?.[meta['dist-tags']?.latest];
      if (!versionData) return [];
      
      const depRisks = [];
      
      const typoWarning = await checkTyposquatting(depName);
      if (typoWarning) {
        depRisks.push(`[Dep ${depName}] ${typoWarning}`);
      }
      
      const scripts = checkScripts(versionData);
      const suspiciousScripts = scripts.filter(s => s.flags && s.flags.length > 0);
      if (suspiciousScripts.length > 0) {
        depRisks.push(`[Dep ${depName}] Suspicious install script: ${suspiciousScripts[0].flags.join(', ')}`);
      }
      
      return depRisks;
    } catch {
      return [];
    }
  };
  
  const results = await Promise.all(depNames.map(checkDep));
  results.forEach(r => risks.push(...r));
  
  return risks;
}

export async function calculateRisk(metadata, pkgVersionData, options = {}) {
  const { skipDeps = false } = options;
  
  let riskScore = 0;
  const details = [];
  
  const pkgName = pkgVersionData.name || metadata.name;
  const version = pkgVersionData.version;

  // 0. Known Malicious Package Check
  if (await isKnownMalicious(pkgName)) {
    riskScore += 100;
    details.push(`🚨 ALARM: Package is on known malicious list`);
  } else if (await isSuspiciousPattern(pkgName)) {
    riskScore += 40;
    details.push(`⚠️ Suspicious package name pattern`);
  } else {
    const isMalicious = await checkMaliciousPackage(pkgName);
    if (isMalicious) {
      riskScore += 80;
      details.push(`🚨 ALARM: Detected as potentially malicious`);
    }
  }

  // 1. Typosquatting Check
  const typoWarning = await checkTyposquatting(pkgName);
  if (typoWarning) {
    riskScore += 80; // Instant high risk
    details.push(`🚨 ALARM: ${typoWarning}`);
  }

  // 2. Vulnerability Check (OSV)
  const vulns = await checkVulnerabilities(pkgName, version);
  if (vulns && vulns.length > 0) {
    riskScore += 50; 
    details.push(`🚨 ALARM: Found ${vulns.length} known CVEs/Vulnerabilities in version ${version}`);
    vulns.forEach(v => details.push(`   - ${v.id}: ${v.summary || 'Known Vulnerability'}`));
  }

  // 3. Script checks
  const dangerousScripts = checkScripts(pkgVersionData);
  if (dangerousScripts.length > 0) {
    dangerousScripts.forEach(script => {
      riskScore += 30; // base risk for having an install script
      details.push(`Contains install script (${script.type})`);
      
      if (script.flags && script.flags.length > 0) {
        riskScore += 50; // massive risk for obfuscation or payload delivery
        details.push(`🚨 ALARM: Suspicious pattern in ${script.type} script -> ${script.flags.join(', ')}`);
      }
    });
  }

  // 4. Dependency Count check
  const depsCount = Object.keys(pkgVersionData.dependencies || {}).length;
  if (depsCount > 100) {
    riskScore += 30;
    details.push(`Extreme number of dependencies (${depsCount})`);
  } else if (depsCount > 50) {
    riskScore += 15;
    details.push(`High number of dependencies (${depsCount})`);
  }

  // 5. Maintainer Age / Last update check
  const timeData = metadata.time || {};
  const createdStr = timeData.created;
  const modifiedStr = timeData.modified;
  
  if (createdStr) {
    const createdDate = new Date(createdStr);
    const ageInDays = (new Date() - createdDate) / (1000 * 60 * 60 * 24);
    if (ageInDays < 14) {
      riskScore += 50; // very new package!
      details.push(`🚨 ALARM: Package is extremely new (created ${Math.floor(ageInDays)} days ago)`);
    } else if (ageInDays < 30) {
      riskScore += 20; 
      details.push(`Package is relatively new (created < 30 days ago)`);
    }
  }

  if (modifiedStr) {
    const modifiedDate = new Date(modifiedStr);
    const updateAgeInDays = (new Date() - modifiedDate) / (1000 * 60 * 60 * 24);
    if (updateAgeInDays > 730) {
      riskScore += 30;
      details.push(`Package is abandoned/unmaintained (not updated in > 2 years)`);
    }
  }

  // 6. Maintainer count check
  const maintainers = pkgVersionData.maintainers || metadata.maintainers || [];
  if (maintainers.length === 1) {
    riskScore += 10;
    details.push(`Only 1 maintainer listed (lower bus factor)`);
  }

  // 7. Dependency infiltration check
  if (!skipDeps) {
    const depRisks = await checkDependencyRisks(pkgVersionData.dependencies, 0, skipDeps);
    if (depRisks.length > 0) {
      riskScore += Math.min(depRisks.length * 15, 30);
      depRisks.slice(0, 3).forEach(r => details.push(`🚨 ALARM: ${r}`));
      if (depRisks.length > 3) {
        details.push(`... and ${depRisks.length - 3} more dependency risks`);
      }
    }
  }

  // 8. License check
  const license = await checkLicense(pkgName);
  if (license && ['NO-LICENSE', 'UNKNOWN', 'UNLICENSED'].includes(license.toUpperCase())) {
    riskScore += 20;
    details.push(`⚠️ No clear license (${license})`);
  } else if (license) {
    details.push(`📄 License: ${license}`);
  }

  // 9. Repository verification
  const repoUrl = await checkRepository(pkgVersionData);
  if (repoUrl) {
    details.push(`📦 Repository: ${repoUrl}`);
  } else {
    riskScore += 15;
    details.push(`⚠️ No verified repository link`);
  }

  return {
    score: Math.min(Math.max(riskScore, 0), 100),
    details,
    metadata: {
      name: pkgName,
      version,
      license,
      repository: repoUrl,
      maintainers: maintainers.length,
      dependencies: depsCount,
      vulnerabilities: vulns?.length || 0
    }
  };
}
