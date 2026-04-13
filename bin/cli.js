#!/usr/bin/env node

import chalk from 'chalk';
import ora from 'ora';
import prompts from 'prompts';
import { fetchPackageMetadata, getLatestVersionData } from '../src/scanner.js';
import { calculateRisk } from '../src/risk.js';
import { installPackage } from '../src/install.js';
import { validatePackageName, sanitizeString } from '../src/security.js';
import { writeFileSync, readFileSync } from 'fs';
import { join } from 'path';
import { cwd } from 'process';

function getVersion() {
  try {
    const pkg = JSON.parse(readFileSync(join(cwd(), 'package.json'), 'utf-8'));
    return pkg.version || '1.0.0';
  } catch {
    return '1.0.0';
  }
}

function generateHtmlReport(reports, options = {}) {
  const multiple = Array.isArray(reports);
  const singleReport = multiple ? null : reports;
  const reportList = multiple ? reports : [reports];
  
  const escapeHtml = (str) => {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };
  
  const getScoreColor = (score) => score > 70 ? '#dc2626' : score >= 40 ? '#f59e0b' : '#16a34a';
  const getScoreLabel = (score) => score > 70 ? 'HIGH RISK' : score >= 40 ? 'MEDIUM RISK' : 'SAFE';
  
  const renderReportItem = (report) => {
    const scoreColor = getScoreColor(report.score);
    const scoreLabel = getScoreLabel(report.score);
    const meta = report.metadata || {};
    
    const detailsHtml = report.details.length > 0 
      ? report.details.map(d => {
          const isAlarm = d.includes('🚨 ALARM');
          const color = isAlarm ? '#dc2626' : '#16a34a';
          return `<li style="color: ${color}; margin: 8px 0;">${escapeHtml(d).replace(/🚨 ALARM:/g, '⚠️').replace(/📄/g, '📋').replace(/📦/g, '📦').replace(/⚠️/g, '⚠️')}</li>`;
        }).join('\n')
      : '<li style="color: #16a34a;">✓ No significant risk factors detected</li>';
    
    return `
    <div class="report-item">
      <div class="report-header">
        <h3>📦 ${escapeHtml(meta.name || 'Unknown Package')}</h3>
        <div class="score-badge" style="background: ${scoreColor}">${report.score}/100 - ${scoreLabel}</div>
      </div>
      <div class="report-details">
        <ul>${detailsHtml}</ul>
      </div>
      <div class="meta-grid">
        <div class="meta-item"><div class="meta-label">Version</div><div class="meta-value">${escapeHtml(meta.version || 'N/A')}</div></div>
        <div class="meta-item"><div class="meta-label">Maintainers</div><div class="meta-value">${meta.maintainers || 0}</div></div>
        <div class="meta-item"><div class="meta-label">Dependencies</div><div class="meta-value">${meta.dependencies || 0}</div></div>
        <div class="meta-item"><div class="meta-label">Vulnerabilities</div><div class="meta-value" style="color: ${meta.vulnerabilities > 0 ? '#dc2626' : '#16a34a'}">${meta.vulnerabilities || 0}</div></div>
        <div class="meta-item"><div class="meta-label">License</div><div class="meta-value">${escapeHtml(meta.license || 'Unknown')}</div></div>
        <div class="meta-item"><div class="meta-label">Repository</div><div class="meta-value">${meta.repository ? `<a href="${escapeHtml(meta.repository)}" target="_blank">${escapeHtml(meta.repository)}</a>` : 'None'}</div></div>
      </div>
    </div>`;
  };
  
  const packagesHtml = reportList.map(renderReportItem).join('\n');
  const title = multiple ? `Security Scan Report (${reportList.length} packages)` : `Security Report - ${singleReport.metadata?.name || 'Package'}`;
  const summaryScore = reportList.reduce((sum, r) => sum + r.score, 0) / reportList.length;
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; margin: 0; padding: 40px; }
    .container { max-width: 900px; margin: 0 auto; }
    .header { background: linear-gradient(135deg, #1e293b, #334155); color: white; padding: 30px; border-radius: 12px 12px 0 0; }
    .header h1 { margin: 0; font-size: 28px; }
    .header p { margin: 10px 0 0; opacity: 0.8; }
    .summary { background: white; padding: 20px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); margin-bottom: 20px; text-align: center; }
    .summary-score { font-size: 32px; font-weight: bold; }
    .report-item { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 20px; }
    .report-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
    .report-header h3 { margin: 0; color: #1e293b; }
    .score-badge { color: white; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; }
    .report-details ul { margin: 0 0 15px; padding-left: 20px; }
    .meta-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
    .meta-item { background: #f1f5f9; padding: 10px; border-radius: 6px; }
    .meta-label { font-size: 11px; color: #64748b; text-transform: uppercase; }
    .meta-value { font-size: 14px; color: #1e293b; font-weight: 500; margin-top: 2px; }
    .meta-value a { color: #2563eb; text-decoration: none; }
    .meta-value a:hover { text-decoration: underline; }
    .footer { text-align: center; color: #94a3b8; font-size: 14px; margin-top: 30px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔒 ${escapeHtml(title)}</h1>
      <p>Generated: ${new Date().toISOString()}</p>
    </div>
    ${multiple ? `<div class="summary"><div class="summary-score" style="color: ${getScoreColor(summaryScore)}">Average Risk Score: ${Math.round(summaryScore)}/100</div></div>` : ''}
    ${packagesHtml}
    <div class="footer">
      Generated by secure-install
    </div>
  </div>
</body>
</html>`;
}

const args = process.argv.slice(2);

function parseArgs() {
  const packageNames = [];
  
  const options = {
    safe: false,
    force: false,
    quick: false,
    verbose: false,
    json: false,
    quiet: false,
    report: false,
    dryRun: false,
    skipDeps: false,
    ci: false,
    output: null,
    threshold: 70
  };
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg.startsWith('--')) {
      const [key, value] = arg.slice(2).split('=');
      
      switch (key) {
        case 'safe':
        case 's':
          options.safe = true;
          break;
        case 'force':
        case 'f':
          options.force = true;
          break;
        case 'quick':
        case 'q':
          options.quick = true;
          break;
        case 'verbose':
        case 'v':
          options.verbose = true;
          break;
        case 'json':
          options.json = true;
          break;
        case 'quiet':
        case 'Q':
          options.quiet = true;
          break;
        case 'report':
        case 'r':
          options.report = true;
          break;
        case 'dry-run':
          options.dryRun = true;
          break;
        case 'skip-deps':
          options.skipDeps = true;
          break;
        case 'ci':
          options.ci = true;
          options.quiet = true;
          break;
        case 'output':
        case 'o':
          options.output = value || args[++i];
          break;
        case 'threshold':
          options.threshold = parseInt(value) || 70;
          break;
        case 'help':
        case 'h':
          showHelp();
          process.exit(0);
          break;
        case 'version':
        case 'V':
          console.log(`secure-install v${getVersion()}`);
          process.exit(0);
          break;
      }
    } else if (!arg.startsWith('-')) {
      packageNames.push(arg);
    }
  }
  
  return { options, packageNames };
}

function showHelp() {
  console.log(`
🔒 secure-install - Secure npm package installer with risk analysis

Usage: secure-install <package1> [package2] ... [options]

Options:
  --safe, -s          Run in safe mode (--ignore-scripts)
  --force, -f         Force installation even on high risk
  --quick, -q         Quick install (--prefer-offline --legacy-peer-deps)
  --verbose, -v       Show verbose npm output
  --json              Output results as JSON
  --quiet, -Q         Quiet mode (no prompts, minimal output)
  --report, -r        Generate HTML security report (no install)
  --dry-run           Analyze packages without installing
  --skip-deps         Skip dependency scanning for faster analysis
  --threshold=<n>     Set risk threshold (default: 70)
  --help, -h          Show this help message

Examples:
  secure-install lodash
  secure-install axios --safe --quick
  secure-install lodash express axios --report
  secure-install sketchy-package --report
  `);
}

const { options, packageNames } = parseArgs();

if (packageNames.length === 0) {
  console.log(chalk.yellow('Usage: secure-install <package> [options]'));
  console.log(chalk.gray('Run --help for more information'));
  process.exit(1);
}

const spinner = options.quiet ? null : ora('Loading security configuration...').start();

async function main() {
  try {
    let validatedNames;
    try {
      validatedNames = await Promise.all(packageNames.map(name => validatePackageName(name)));
    } catch (err) {
      if (spinner) spinner.fail('Validation failed');
      console.error(chalk.red(`Invalid package name: ${err.message}`));
      process.exit(1);
    }
    
    if (spinner) spinner.text = 'Fetching package metadata from npm registry...';
    
    const reports = [];
    
    for (let i = 0; i < validatedNames.length; i++) {
      const pkgName = validatedNames[i];
      
      if (spinner) {
        spinner.text = `Analyzing ${pkgName} (${i + 1}/${validatedNames.length})...`;
      }
      
      if (!options.quiet && validatedNames.length > 1) {
        console.log(chalk.cyan(`\n📦 Analyzing ${pkgName}...`));
      }
      
      const metadata = await fetchPackageMetadata(pkgName);
      const versionData = getLatestVersionData(metadata);
      const report = await calculateRisk(metadata, versionData, { skipDeps: options.skipDeps });
      reports.push(report);
    }
    
    if (spinner) spinner.stop();
    
    if (options.json) {
      if (validatedNames.length === 1) {
        console.log(JSON.stringify(reports[0], null, 2));
      } else {
        console.log(JSON.stringify(reports, null, 2));
      }
      
      if (options.report || options.dryRun || options.ci) {
        process.exit(0);
      }
    } else {
      if (validatedNames.length === 1) {
        const report = reports[0];
        const safePackageName = sanitizeString(validatedNames[0], 100);
        console.log(chalk.cyan(`\n🔒 secure-install: Analyzing ${chalk.bold(safePackageName)}...\n`));
        
        console.log(chalk.bold.underline('📊 Security Report'));
        
        let scoreColor = chalk.green;
        if (report.score > 70) scoreColor = chalk.red;
        else if (report.score >= 40) scoreColor = chalk.yellow;
        
        console.log(`Risk Score: ${scoreColor(report.score + '/100')}`);
        
        if (report.details.length > 0) {
          console.log(chalk.bold('\n📋 Analysis Details:'));
          report.details.forEach(detail => {
            const isWarning = detail.includes('🚨 ALARM');
            console.log(isWarning ? ` - ${chalk.red(detail)}` : ` - ${chalk.green(detail)}`);
          });
        } else {
          console.log(chalk.green('\n✓ No significant risk factors detected.'));
        }
        
        if (report.metadata) {
          console.log(chalk.bold('\n📦 Package Info:'));
          console.log(`   Version: ${report.metadata.version}`);
          console.log(`   Maintainers: ${report.metadata.maintainers}`);
          console.log(`   Dependencies: ${report.metadata.dependencies}`);
          if (report.metadata.vulnerabilities > 0) {
            console.log(chalk.red(`   Vulnerabilities: ${report.metadata.vulnerabilities}`));
          }
          if (report.metadata.license) {
            console.log(`   License: ${report.metadata.license}`);
          }
          if (report.metadata.repository) {
            console.log(`   Repo: ${chalk.blue(report.metadata.repository)}`);
          }
        }
        console.log('');
      } else {
        reports.forEach((report, i) => {
          const pkgName = validatedNames[i];
          let scoreColor = chalk.green;
          if (report.score > 70) scoreColor = chalk.red;
          else if (report.score >= 40) scoreColor = chalk.yellow;
          
          console.log(chalk.bold(`\n📦 ${pkgName}: ${scoreColor(report.score + '/100')}`));
          
          report.details.slice(0, 3).forEach(detail => {
            const isWarning = detail.includes('🚨 ALARM');
            console.log(isWarning ? `   ${chalk.red('⚠️ ' + detail)}` : `   ${chalk.green(detail)}`);
          });
        });
        console.log('');
      }
    }
    
    if (options.report || options.dryRun) {
      const htmlReport = generateHtmlReport(reports);
      const filename = options.output || (validatedNames.length === 1 
        ? `security-report-${validatedNames[0]}-${Date.now()}.html`
        : `security-report-${Date.now()}.html`);
      const filepath = join(cwd(), filename);
      
      writeFileSync(filepath, htmlReport);
      if (!options.quiet) {
        console.log(chalk.green(`\n📄 HTML report saved to: ${filename}`));
        console.log(chalk.gray(options.dryRun ? '🔍 Dry run complete (no installation)' : '📋 Report only mode'));
      }
      
      const hasHighRisk = reports.some(r => r.score > options.threshold);
      process.exit(hasHighRisk && !options.force ? 1 : 0);
    }
    
    const highRisk = reports.find(r => r.score > options.threshold && !options.force);
    if (highRisk) {
      if (!options.quiet) {
        const pkgIndex = reports.indexOf(highRisk);
        console.log(chalk.bgRed.white.bold(' 🛑 BLOCKED: High Risk '));
        console.log(chalk.red(`Package ${validatedNames[pkgIndex]} has risk score ${highRisk.score} exceeding threshold ${options.threshold}`));
        console.log(`Use ${chalk.bold('--force')} to bypass or ${chalk.bold('--threshold=<n>')} to adjust\n`);
      }
      process.exit(1);
    }
    
    const hasMediumRisk = reports.some(r => r.score >= 40);
    
    for (let i = 0; i < validatedNames.length; i++) {
      const pkgName = validatedNames[i];
      const report = reports[i];
      
      if (report.score >= 40 && !options.force && !options.quiet && validatedNames.length === 1) {
        const response = await prompts({
          type: 'confirm',
          name: 'continue',
          message: chalk.yellow('High risk factors detected. Continue with installation?'),
          initial: false
        });
        
        if (!response.continue) {
          console.log(chalk.red('\n❌ Installation aborted\n'));
          process.exit(0);
        }
      }
      
      console.log(chalk.blue(`\n🚀 Installing ${pkgName}...`));
      if (options.safe) console.log(chalk.green('🛡️ Safe Mode ENABLED'));
      if (options.quick) console.log(chalk.green('⚡ Quick Mode ENABLED'));
      if (options.verbose) console.log(chalk.green('📝 Verbose Mode ENABLED'));
      
      await installPackage(pkgName, { 
        safe: options.safe, 
        quick: options.quick, 
        verbose: options.verbose 
      });
      
      console.log(chalk.green.bold(`\n✅ Successfully installed ${pkgName}!\n`));
    }
    
  } catch (error) {
    if (spinner) spinner.fail('Error');
    console.error(chalk.red(error.message));
    process.exit(1);
  }
}

main();