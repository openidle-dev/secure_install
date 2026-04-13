import { spawn } from 'child_process';
import { validatePackageName } from './security.js';

const DEFAULT_TIMEOUT = 5 * 60 * 1000;

function buildInstallArgs(pkgName, options = {}) {
  const args = ['install', pkgName, '--no-audit', '--no-fund'];
  
  if (options.verbose) {
    args.push('--verbose');
  }
  
  if (options.safe) {
    args.push('--ignore-scripts');
  }

  if (options.quick) {
    args.push('--prefer-offline', '--legacy-peer-deps');
  }

  return args;
}

export function installPackage(pkgName, options = {}) {
  const validatedName = validatePackageName(pkgName);
  const timeout = options.timeout || DEFAULT_TIMEOUT;
  
  return new Promise((resolve, reject) => {
    const args = buildInstallArgs(validatedName, options);
    const isWindows = /^win/.test(process.platform);
    const command = isWindows ? 'npm.cmd' : 'npm';
    
    const child = spawn(command, args, {
      stdio: options.verbose ? 'inherit' : 'pipe',
      shell: false,
      env: { ...process.env, npm_config_unsafe_perm: 'false' }
    });

    let stdoutData = '';
    let stderrData = '';
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
      reject(new Error('Installation timed out - possible infinite loop or malicious script'));
    }, timeout);

    if (!options.verbose) {
      child.stdout.on('data', (data) => {
        stdoutData += data;
        process.stdout.write(data);
      });
      
      child.stderr.on('data', (data) => {
        stderrData += data;
        process.stderr.write(data);
      });
    }

    child.on('close', (code) => {
      clearTimeout(timer);
      
      if (timedOut) return;
      
      if (code === 0) {
        resolve();
      } else {
        const errorMsg = stderrData.includes('EACCES') 
          ? 'Permission denied - try using --safe mode'
          : `npm install failed with code ${code}`;
        reject(new Error(errorMsg));
      }
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(new Error(`Failed to execute npm: ${err.message}`));
    });
  });
}