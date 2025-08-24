/**
 * 3axf Design a Secure Automation Script Analyzer
 *
 * This script analyzer is designed to identify and flag potential security vulnerabilities
 * in automation scripts. It uses a combination of static code analysis and runtime
 * checks to detect common security issues.
 *
 * Configuration:
 *   - scriptDir: the directory containing the automation scripts to analyze
 *   - reportDir: the directory to write the analysis report
 *   - allowedExecutables: an array of allowed executable files or commands
 *   - disallowedExecutables: an array of disallowed executable files or commands
 *
 * Usage:
 *   1. Set the configuration options below
 *   2. Run the script with Node.js (e.g. `node 3axf_design_a_secure.js`)
 *   3. Review the analysis report in the reportDir
 */

// Configuration
const scriptDir = './scripts';
const reportDir = './reports';
const allowedExecutables = ['python', 'bash'];
const disallowedExecutables = [' powershell.exe', 'cmd.exe'];

// Import required modules
const fs = require('fs');
const path = require('path');
const exec = require('child_process').exec;

// Function to analyze a script file
function analyzeScript(file) {
  // Read the script file contents
  const scriptContent = fs.readFileSync(file, 'utf8');

  // Check for disallowed executables
  disallowedExecutables.forEach((executable) => {
    if (scriptContent.includes(executable)) {
      console.log(`Security warning: Disallowed executable '${executable}' found in ${file}`);
    }
  });

  // Check for allowed executables
  allowedExecutables.forEach((executable) => {
    if (scriptContent.includes(executable)) {
      console.log(`Info: Allowed executable '${executable}' found in ${file}`);
    }
  });

  // Run a static code analysis tool (e.g. ESLint) on the script
  const eslintOutput = exec(`eslint ${file}`);
  console.log(eslintOutput.stdout);

  // Generate a report for the script
  const report = `Script: ${file}
Allowed executables: ${allowedExecutables.join(', ')}
Disallowed executables: ${disallowedExecutables.join(', ')}
ESLint output: ${eslintOutput.stdout}
`;
  fs.writeFileSync(`${reportDir}/${path.basename(file)}.report`, report);
}

// Analyze all script files in the scriptDir
fs.readdir(scriptDir, (err, files) => {
  if (err) {
    console.error(err);
    return;
  }

  files.forEach((file) => {
    const filePath = `${scriptDir}/${file}`;
    if (fs.lstatSync(filePath).isFile()) {
      analyzeScript(filePath);
    }
  });
});