export function checkScripts(pkgVersionData) {
  const scripts = pkgVersionData.scripts || {};
  const dangerous = [];
  
  const riskyHooks = ["preinstall", "install", "postinstall", "prepublish", "prepare", "prepack"];
  
  const networkPatterns = [
    { regex: /fetch\s*\(/, flag: "Network fetch call" },
    { regex: /http\.(get|post|request)\s*\(/, flag: "HTTP request" },
    { regex: /https\.(get|post|request)\s*\(/, flag: "HTTPS request" },
    { regex: /require\s*\(\s*['"]http/, flag: "HTTP module usage" },
    { regex: /require\s*\(\s*['"]https/, flag: "HTTPS module usage" },
    { regex: /net\.connect\s*\(/, flag: "TCP socket connection" },
    { regex: /dns\.resolve\s*\(/, flag: "DNS lookup" },
    { regex: /child_process.*spawn.*curl/, flag: "curl network call" },
    { regex: /child_process.*spawn.*wget/, flag: "wget network call" },
    { regex: /child_process.*exec.*wget/, flag: "wget network call" },
    { regex: /child_process.*exec.*curl/, flag: "curl network call" },
    { regex: /\$?\(\s*curl\s+/, flag: "Shell curl execution" },
    { regex: /\$?\(\s*wget\s+/, flag: "Shell wget execution" },
    { regex: /\.send\s*\(\s*['"]http/, flag: "HTTP send" },
    { regex: /new\s+WebSocket\s*\(/, flag: "WebSocket connection" },
    { regex: /\x68\x74\x74\x70/, flag: "HTTP (hex encoded)" }
  ];
  
  const exfilPatterns = [
    { regex: /process\.env\./, flag: "Accessing environment variables" },
    { regex: /JSON\.stringify\s*\(\s*process\.env/, flag: "Exfiltrating env vars" },
    { regex: /console\.log\s*\(\s*process\.env/, flag: "Logging env vars" },
    { regex: /fs\.writeFile.*process\.env/, flag: "Writing env to file" },
    { regex: /process\.env\["?(TOKEN|PASS|KEY|SECRET|API|CREDENTIAL|PRIVATE)/i, flag: "Accessing secrets" },
    { regex: /process\.env\.npm/, flag: "Accessing npm config" },
    { regex: /__dirname/, flag: "Accessing directory path" },
    { regex: /__filename/, flag: "Accessing file path" },
    { regex: /require\s*\(\s*['"]fs['"]\).*readFileSync.*password/, flag: "Reading password files" },
    { regex: /os\.userInfo\s*\(/, flag: "Getting user info" },
    { regex: /os\.homedir\s*\(/, flag: "Getting home directory" },
    { regex: /hostname/, flag: "Getting hostname" },
    { regex: /platform/, flag: "Getting platform info" },
    { regex: /exit\s*\(/, flag: "Exit process" },
    { regex: /process\.exit\s*\(/, flag: "Exit process" }
  ];
  
  const obfuscationPatterns = [
    { regex: /curl\s+.*?\|/, flag: "Piping curl to shell" },
    { regex: /wget\s+.*?\|/, flag: "Piping wget to shell" },
    { regex: /eval\s*\(/, flag: "Dynamic execution via eval()" },
    { regex: /Buffer\.from\s*\(\s*['"][A-Za-z0-9+\/=]{20,}/, flag: "Base64 payload" },
    { regex: /\\x[0-9a-fA-F]{2}/, flag: "Hex-encoded payload" },
    { regex: /rm\s+-rf\s+\//, flag: "Destructive file removal" },
    { regex: /nc\s+-e/, flag: "Netcat reverse shell" },
    { regex: /\/dev\/tcp\//, flag: "Bash reverse shell" },
    { regex: /atob\s*\(/, flag: "Base64 decoding" },
    { regex: /\.replace\s*\(\s*\/.*\/.*['"]g['"]\s*,\s*['"][a-zA-Z0-9+\/=]/, flag: "Decoding payload" },
    { regex: /require\s*\(\s*['"]crypto['"]/, flag: "Cryptography module" },
    { regex: /require\s*\(\s*['"]child_process['"]/, flag: "Child process module" },
    { regex: /new\s+Function\s*\(/, flag: "Dynamic function creation" },
    { regex: /setTimeout\s*\(\s*['"]/, flag: "Delayed execution" },
    { regex: /setInterval\s*\(\s*['"]/, flag: "Interval execution" }
  ];

  const allPatterns = [...obfuscationPatterns, ...networkPatterns, ...exfilPatterns];
  
  riskyHooks.forEach(hook => {
    if (scripts[hook]) {
      const scriptContent = scripts[hook];
      const flags = [];
      const categories = { obfuscation: [], network: [], exfil: [] };
      
      allPatterns.forEach(pattern => {
        if (pattern.regex.test(scriptContent)) {
          const flag = pattern.flag;
          flags.push(flag);
          
          if (obfuscationPatterns.some(p => p.flag === flag)) {
            categories.obfuscation.push(flag);
          } else if (networkPatterns.some(p => p.flag === flag)) {
            categories.network.push(flag);
          } else if (exfilPatterns.some(p => p.flag === flag)) {
            categories.exfil.push(flag);
          }
        }
      });

      if (flags.length > 0) {
        dangerous.push({
          type: hook,
          content: scriptContent,
          flags: [...new Set(flags)],
          categories: {
            obfuscation: [...new Set(categories.obfuscation)],
            network: [...new Set(categories.network)],
            exfil: [...new Set(categories.exfil)]
          }
        });
      }
    }
  });

  return dangerous;
}