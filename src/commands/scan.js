/**
 * Scan Command - Local repository security scanning
 */

const { Command } = require('commander')
const chalk = require('chalk')
const ora = require('ora')
const fs = require('fs-extra')
const path = require('path')
const glob = require('glob')
const ignore = require('ignore')

const LocalScanner = require('../services/local-scanner')
const { getAPIClient } = require('../services/api-client')
const ConfigManager = require('../utils/config-manager')
const ReportGenerator = require('../utils/report-generator')

const scanCommand = new Command('scan')
  .description('Scan repository for AI-generated security vulnerabilities')
  .argument('[path]', 'repository path to scan', '.')
  .option('-r, --remote', 'sync results to Vaultace cloud')
  .option('-f, --format <format>', 'output format (table|json|csv|sarif)', 'table')
  .option('-o, --output <file>', 'output file path')
  .option('--severity <level>', 'minimum severity level (low|medium|high|critical)', 'medium')
  .option('--exclude <patterns...>', 'exclude file patterns')
  .option('--include <patterns...>', 'include only these patterns')
  .option('--no-gitignore', 'ignore .gitignore rules')
  .option('--ai-patterns', 'focus on AI-generated code patterns')
  .option('--framework <name>', 'target framework (react|nextjs|fastapi|django)')
  .option('--ci', 'CI mode - fail on vulnerabilities')
  .action(async (scanPath, options) => {
    const spinner = ora('Initializing Vaultace security scanner...').start()
    
    try {
      // Resolve scan path
      const fullPath = path.resolve(scanPath)
      
      if (!await fs.exists(fullPath)) {
        throw new Error(`Path does not exist: ${scanPath}`)
      }
      
      // Initialize scanner
      const scanner = new LocalScanner({
        path: fullPath,
        severity: options.severity,
        exclude: options.exclude || [],
        include: options.include || [],
        respectGitignore: options.gitignore,
        aiPatterns: options.aiPatterns,
        framework: options.framework,
        verbose: options.parent?.opts()?.verbose || false
      })
      
      spinner.text = 'Scanning repository for vulnerabilities...'
      
      // Run security scan
      const results = await scanner.scan()
      
      spinner.succeed(`Scan completed: ${results.vulnerabilities.length} vulnerabilities found`)
      
      // Generate report
      const reporter = new ReportGenerator(options.format)
      const report = await reporter.generate(results)
      
      // Output results
      if (options.output) {
        await fs.writeFile(options.output, report)
        console.log(chalk.green(`Report saved to: ${options.output}`))
      } else {
        console.log(report)
      }
      
      // Sync to cloud if requested
      if (options.remote) {
        await syncToCloud(results, options)
      }
      
      // Display summary
      displayScanSummary(results)
      
      // CI mode - exit with error if vulnerabilities found
      if (options.ci) {
        const criticalCount = results.vulnerabilities.filter(v => v.severity === 'critical').length
        const highCount = results.vulnerabilities.filter(v => v.severity === 'high').length
        
        if (criticalCount > 0 || highCount > 0) {
          console.error(chalk.red(`\n❌ CI Check Failed: ${criticalCount} critical, ${highCount} high severity vulnerabilities`))
          process.exit(1)
        } else {
          console.log(chalk.green('\n✅ CI Check Passed: No high/critical vulnerabilities found'))
        }
      }
      
    } catch (error) {
      spinner.fail(`Scan failed: ${error.message}`)
      
      if (options.parent?.opts()?.verbose) {
        console.error(chalk.red(error.stack))
      }
      
      process.exit(1)
    }
  })

async function syncToCloud(results, options) {
  const syncSpinner = ora('Syncing results to Vaultace cloud...').start()
  
  try {
    const config = ConfigManager.getConfig()
    
    if (!config.auth?.accessToken) {
      syncSpinner.warn('Not authenticated - run "vaultace auth login" first')
      return
    }
    
    const apiClient = new APIClient(config)
    await apiClient.uploadScanResults(results)
    
    syncSpinner.succeed('Results synced to Vaultace cloud')
    console.log(chalk.blue(`View results: https://app.vaultace.com/scans/${results.scanId}`))
    
  } catch (error) {
    syncSpinner.fail(`Cloud sync failed: ${error.message}`)
  }
}

function displayScanSummary(results) {
  const { vulnerabilities, stats } = results
  
  console.log(chalk.bold('\n📊 Scan Summary'))
  console.log('─'.repeat(40))
  
  // Vulnerability counts by severity
  const severityCounts = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length
  }
  
  console.log(`${chalk.red('🔴 Critical:')} ${severityCounts.critical}`)
  console.log(`${chalk.yellow('🟡 High:')} ${severityCounts.high}`)
  console.log(`${chalk.blue('🔵 Medium:')} ${severityCounts.medium}`) 
  console.log(`${chalk.gray('⚪ Low:')} ${severityCounts.low}`)
  
  console.log(`\n${chalk.bold('Files Scanned:')} ${stats.filesScanned}`)
  console.log(`${chalk.bold('Lines of Code:')} ${stats.linesScanned.toLocaleString()}`)
  console.log(`${chalk.bold('Scan Time:')} ${stats.scanDuration}ms`)
  
  // AI-specific patterns found
  if (stats.aiPatternsFound > 0) {
    console.log(`\n${chalk.magenta('🤖 AI Patterns Found:')} ${stats.aiPatternsFound}`)
    console.log(chalk.gray('   Potential AI-generated vulnerabilities detected'))
  }
  
  // Top vulnerability types
  if (vulnerabilities.length > 0) {
    const typecounts = {}
    vulnerabilities.forEach(v => {
      typecounts[v.type] = (typecounts[v.type] || 0) + 1
    })
    
    const topTypes = Object.entries(typecounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 3)
    
    if (topTypes.length > 0) {
      console.log(`\n${chalk.bold('🔍 Top Issues:')}`)
      topTypes.forEach(([type, count]) => {
        console.log(`   ${type}: ${count}`)
      })
    }
  }
  
  // Recommendations
  console.log(`\n${chalk.bold('💡 Next Steps:')}`)
  
  if (severityCounts.critical > 0) {
    console.log(chalk.red('   • Fix critical vulnerabilities immediately'))
  }
  
  if (severityCounts.high > 0) {
    console.log(chalk.yellow('   • Address high-severity issues'))
  }
  
  if (stats.aiPatternsFound > 0) {
    console.log(chalk.magenta('   • Review AI-generated code sections'))
  }
  
  console.log(chalk.gray('   • Run with --remote to sync to dashboard'))
  console.log(chalk.gray('   • Use vaultace repo add <url> to monitor continuously'))
}

module.exports = scanCommand