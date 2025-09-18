/**
 * Repository Command
 * Manage repositories for continuous monitoring
 */

const { Command } = require('commander')
const chalk = require('chalk')
const inquirer = require('inquirer')
const ora = require('ora')
const { table } = require('table')

const APIClient = require('../services/api-client')
const ConfigManager = require('../utils/config-manager')

const repoCommand = new Command('repo')
  .description('Manage repositories for continuous monitoring')

// List repositories
repoCommand
  .command('list')
  .alias('ls')
  .description('List monitored repositories')
  .action(async () => {
    const config = ConfigManager.getConfig()
    
    if (!config.auth?.accessToken) {
      console.error(chalk.red('❌ Not authenticated. Run vaultace auth login first.'))
      process.exit(1)
    }
    
    const spinner = ora('Fetching repositories...').start()
    
    try {
      const apiClient = new APIClient(config)
      const repositories = await apiClient.getRepositories()
      
      spinner.stop()
      
      if (repositories.length === 0) {
        console.log(chalk.gray('No repositories configured'))
        console.log(chalk.gray('Use vaultace repo add <url> to add a repository'))
        return
      }
      
      // Create table
      const tableData = [
        [chalk.bold('Name'), chalk.bold('Provider'), chalk.bold('Branch'), chalk.bold('Status'), chalk.bold('Last Scan')]
      ]
      
      repositories.forEach(repo => {
        const statusColor = repo.scan_enabled ? chalk.green : chalk.gray
        const lastScan = repo.last_scan_at 
          ? new Date(repo.last_scan_at).toLocaleDateString()
          : 'Never'
        
        tableData.push([
          repo.name,
          repo.provider,
          repo.branch || 'main',
          statusColor(repo.scan_enabled ? 'Active' : 'Inactive'),
          lastScan
        ])
      })
      
      console.log(table(tableData, {
        border: {
          topBody: '─',
          topJoin: '┬',
          topLeft: '┌',
          topRight: '┐',
          bottomBody: '─',
          bottomJoin: '┴',
          bottomLeft: '└',
          bottomRight: '┘',
          bodyLeft: '│',
          bodyRight: '│',
          bodyJoin: '│'
        }
      }))
      
    } catch (error) {
      spinner.fail(`Failed to fetch repositories: ${error.message}`)
      process.exit(1)
    }
  })

// Add repository
repoCommand
  .command('add')
  .description('Add repository for monitoring')
  .argument('<url>', 'repository URL')
  .option('-n, --name <name>', 'repository display name')
  .option('-b, --branch <branch>', 'branch to monitor', 'main')
  .option('-p, --provider <provider>', 'provider (github|gitlab|bitbucket)', 'github')
  .action(async (url, options) => {
    const config = ConfigManager.getConfig()
    
    if (!config.auth?.accessToken) {
      console.error(chalk.red('❌ Not authenticated. Run vaultace auth login first.'))
      process.exit(1)
    }
    
    try {
      // Extract repository name from URL if not provided
      let repoName = options.name
      if (!repoName) {
        const urlParts = url.replace(/\.git$/, '').split('/')
        repoName = urlParts[urlParts.length - 1]
      }
      
      // Validate provider
      const validProviders = ['github', 'gitlab', 'bitbucket']
      if (!validProviders.includes(options.provider.toLowerCase())) {
        console.error(chalk.red(`Invalid provider. Must be one of: ${validProviders.join(', ')}`))
        process.exit(1)
      }
      
      const spinner = ora(`Adding repository ${repoName}...`).start()
      
      const apiClient = new APIClient(config)
      const repository = await apiClient.addRepository(
        repoName,
        url,
        options.provider.toLowerCase(),
        options.branch
      )
      
      spinner.succeed(`Repository ${repoName} added successfully!`)
      
      console.log(chalk.green('\n✅ Repository configured'))
      console.log(`${chalk.bold('Name:')} ${repository.name}`)
      console.log(`${chalk.bold('URL:')} ${repository.url}`)
      console.log(`${chalk.bold('Provider:')} ${repository.provider}`)
      console.log(`${chalk.bold('Branch:')} ${repository.branch}`)
      
      console.log(chalk.blue('\n🔍 Next steps:'))
      console.log('• Repository will be scanned automatically')
      console.log('• View results at: https://app.vaultace.com')
      console.log('• Run local scans with: vaultace scan --remote')
      
    } catch (error) {
      console.error(chalk.red(`Failed to add repository: ${error.message}`))
      
      if (error.message.includes('already exists')) {
        console.log(chalk.gray('Use vaultace repo list to see existing repositories'))
      }
      
      process.exit(1)
    }
  })

// Remove repository
repoCommand
  .command('remove')
  .alias('rm')
  .description('Remove repository from monitoring')
  .argument('<name-or-id>', 'repository name or ID')
  .option('-f, --force', 'skip confirmation prompt')
  .action(async (nameOrId, options) => {
    const config = ConfigManager.getConfig()
    
    if (!config.auth?.accessToken) {
      console.error(chalk.red('❌ Not authenticated. Run vaultace auth login first.'))
      process.exit(1)
    }
    
    try {
      const apiClient = new APIClient(config)
      
      // Get repositories to find the one to remove
      const repositories = await apiClient.getRepositories()
      const repository = repositories.find(r => 
        r.name === nameOrId || r.id === nameOrId
      )
      
      if (!repository) {
        console.error(chalk.red(`Repository not found: ${nameOrId}`))
        console.log(chalk.gray('Use vaultace repo list to see available repositories'))
        process.exit(1)
      }
      
      // Confirmation
      if (!options.force) {
        const { confirm } = await inquirer.prompt([{
          type: 'confirm',
          name: 'confirm',
          message: `Remove repository "${repository.name}"?`,
          default: false
        }])
        
        if (!confirm) {
          console.log(chalk.gray('Operation cancelled'))
          return
        }
      }
      
      const spinner = ora(`Removing repository ${repository.name}...`).start()
      
      await apiClient.removeRepository(repository.id)
      
      spinner.succeed(`Repository ${repository.name} removed`)
      
    } catch (error) {
      console.error(chalk.red(`Failed to remove repository: ${error.message}`))
      process.exit(1)
    }
  })

// Status subcommand
repoCommand
  .command('status')
  .description('Show repository monitoring status')
  .action(async () => {
    const config = ConfigManager.getConfig()
    
    if (!config.auth?.accessToken) {
      console.error(chalk.red('❌ Not authenticated. Run vaultace auth login first.'))
      process.exit(1)
    }
    
    const spinner = ora('Checking repository status...').start()
    
    try {
      const apiClient = new APIClient(config)
      const repositories = await apiClient.getRepositories()
      
      spinner.stop()
      
      if (repositories.length === 0) {
        console.log(chalk.gray('No repositories configured'))
        return
      }
      
      console.log(chalk.bold(`\n📊 Repository Status (${repositories.length} total)\n`))
      
      const activeRepos = repositories.filter(r => r.scan_enabled)
      const inactiveRepos = repositories.filter(r => !r.scan_enabled)
      
      console.log(`${chalk.green('✅ Active:')} ${activeRepos.length}`)
      console.log(`${chalk.gray('⭕ Inactive:')} ${inactiveRepos.length}`)
      
      // Recent scan activity
      const recentScans = repositories
        .filter(r => r.last_scan_at)
        .sort((a, b) => new Date(b.last_scan_at) - new Date(a.last_scan_at))
        .slice(0, 3)
      
      if (recentScans.length > 0) {
        console.log(chalk.bold('\n🕒 Recent Activity:'))
        recentScans.forEach(repo => {
          const scanTime = new Date(repo.last_scan_at).toLocaleString()
          console.log(`   ${repo.name} - ${scanTime}`)
        })
      }
      
      console.log(chalk.blue('\n💡 Commands:'))
      console.log('   vaultace repo add <url>    # Add repository')
      console.log('   vaultace scan --remote     # Manual scan')
      console.log('   https://app.vaultace.com   # View dashboard')
      
    } catch (error) {
      spinner.fail(`Failed to get repository status: ${error.message}`)
      process.exit(1)
    }
  })

module.exports = repoCommand