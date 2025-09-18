#!/usr/bin/env node

const { Command } = require('commander');
const chalk = require('chalk');
const packageJson = require('../package.json');

const program = new Command();

program
  .name('vaultace')
  .description('Vaultace CLI - Security scanning and workflow automation')
  .version(packageJson.version);

program
  .command('scan [path]')
  .description('Scan directory for security vulnerabilities')
  .option('-r, --recursive', 'Scan recursively')
  .option('-o, --output <file>', 'Output results to file')
  .action((path = '.', options) => {
    console.log(chalk.blue('🔍 Starting security scan...'));
    console.log(`Scanning: ${path}`);
    // Implementation will be synced from private repo
  });

program
  .command('workflow')
  .description('Workflow management commands')
  .command('run <workflow>')
  .description('Run a security workflow')
  .action((workflow) => {
    console.log(chalk.green(`🔄 Running workflow: ${workflow}`));
    // Implementation will be synced from private repo
  });

program
  .command('report')
  .description('Generate security reports')
  .command('generate [type]')
  .description('Generate security report')
  .action((type = 'summary') => {
    console.log(chalk.yellow(`📊 Generating ${type} report...`));
    // Implementation will be synced from private repo
  });

if (process.argv.length === 2) {
  program.help();
}

program.parse();
