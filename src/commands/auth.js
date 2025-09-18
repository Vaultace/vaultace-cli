/**
 * Authentication Command
 * Login, logout, and authentication status management
 */

const { Command } = require('commander')
const chalk = require('chalk')
const inquirer = require('inquirer')
const ora = require('ora')

const APIClient = require('../services/api-client')
const ConfigManager = require('../utils/config-manager')

const authCommand = new Command('auth')
  .description('Vaultace authentication management')

// Login subcommand
authCommand
  .command('login')
  .description('Login to Vaultace')
  .option('-e, --email <email>', 'email address')
  .option('-p, --password <password>', 'password')
  .option('-r, --remember', 'remember login for longer')
  .action(async (options) => {
    const spinner = ora('Authenticating with Vaultace...').start()
    
    try {
      let { email, password } = options
      
      // Prompt for credentials if not provided
      if (!email || !password) {
        spinner.stop()
        
        const answers = await inquirer.prompt([
          {
            type: 'input',
            name: 'email',
            message: 'Email:',
            when: !email,
            validate: (input) => {
              const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
              return emailRegex.test(input) || 'Please enter a valid email address'
            }
          },
          {
            type: 'password',
            name: 'password',
            message: 'Password:',
            when: !password,
            mask: '*',
            validate: (input) => input.length >= 8 || 'Password must be at least 8 characters'
          }
        ])
        
        email = email || answers.email
        password = password || answers.password
        
        spinner.start('Authenticating with Vaultace...')
      }
      
      // Authenticate
      const apiClient = new APIClient()
      await apiClient.login(email, password, options.remember)
      
      // Get user info
      const userInfo = await apiClient.getCurrentUser()
      
      spinner.succeed('Successfully logged in to Vaultace!')
      
      console.log(chalk.green('\n✅ Authentication successful'))
      console.log(`${chalk.bold('User:')} ${userInfo.email}`)
      console.log(`${chalk.bold('Organization:')} ${userInfo.organization_id}`)
      console.log(`${chalk.bold('Role:')} ${userInfo.role}`)
      
      if (!userInfo.is_verified) {
        console.log(chalk.yellow('\n⚠️  Email verification pending'))
        console.log('Please check your email and verify your account')
      }
      
    } catch (error) {
      spinner.fail(`Login failed: ${error.message}`)
      
      if (error.message.includes('Invalid credentials')) {
        console.log(chalk.gray('\nTips:'))
        console.log(chalk.gray('• Check your email and password'))
        console.log(chalk.gray('• Use vaultace auth register to create an account'))
      }
      
      process.exit(1)
    }
  })

// Register subcommand
authCommand
  .command('register')
  .description('Create new Vaultace account')
  .action(async () => {
    console.log(chalk.bold.cyan('🛡️  Create Your Vaultace Account\n'))
    
    try {
      const answers = await inquirer.prompt([
        {
          type: 'input',
          name: 'organizationName',
          message: 'Organization name:',
          validate: (input) => input.trim().length >= 2 || 'Organization name must be at least 2 characters'
        },
        {
          type: 'input',
          name: 'organizationSlug',
          message: 'Organization slug (lowercase, alphanumeric with dashes):',
          validate: (input) => {
            const slugRegex = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/
            return slugRegex.test(input) || 'Invalid slug format (use lowercase, numbers, and dashes only)'
          },
          transformer: (input) => input.toLowerCase().replace(/[^a-z0-9-]/g, '-')
        },
        {
          type: 'input',
          name: 'email',
          message: 'Email address:',
          validate: (input) => {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
            return emailRegex.test(input) || 'Please enter a valid email address'
          }
        },
        {
          type: 'password',
          name: 'password',
          message: 'Password (min 8 characters):',
          mask: '*',
          validate: (input) => {
            if (input.length < 8) {return 'Password must be at least 8 characters'}
            if (!/(?=.*[a-z])/.test(input)) {return 'Password must contain lowercase letters'}
            if (!/(?=.*[A-Z])/.test(input)) {return 'Password must contain uppercase letters'}
            if (!/(?=.*\d)/.test(input)) {return 'Password must contain numbers'}
            return true
          }
        },
        {
          type: 'input',
          name: 'firstName',
          message: 'First name:',
          validate: (input) => input.trim().length > 0 || 'First name is required'
        },
        {
          type: 'input',
          name: 'lastName',
          message: 'Last name:',
          validate: (input) => input.trim().length > 0 || 'Last name is required'
        }
      ])
      
      const spinner = ora('Creating your Vaultace account...').start()
      
      const apiClient = new APIClient()
      const userInfo = await apiClient.register(
        answers.organizationName,
        answers.organizationSlug,
        answers.email,
        answers.password,
        answers.firstName,
        answers.lastName
      )
      
      spinner.succeed('Account created successfully!')
      
      console.log(chalk.green('\n🎉 Welcome to Vaultace!'))
      console.log(`${chalk.bold('User:')} ${userInfo.email}`)
      console.log(`${chalk.bold('Organization:')} ${answers.organizationName}`)
      console.log(`${chalk.bold('Slug:')} ${answers.organizationSlug}`)
      
      console.log(chalk.yellow('\n📧 Next steps:'))
      console.log('1. Check your email for verification link')
      console.log('2. Login with: vaultace auth login')
      console.log('3. Start scanning: vaultace scan')
      
    } catch (error) {
      console.error(chalk.red(`Registration failed: ${error.message}`))
      
      if (error.message.includes('already exists')) {
        console.log(chalk.gray('\nTry using vaultace auth login instead'))
      }
      
      process.exit(1)
    }
  })

// Logout subcommand
authCommand
  .command('logout')
  .description('Logout from Vaultace')
  .action(async () => {
    const config = ConfigManager.getConfig()
    
    if (!config.auth?.accessToken) {
      console.log(chalk.gray('Not currently logged in'))
      return
    }
    
    const spinner = ora('Logging out...').start()
    
    try {
      const apiClient = new APIClient(config)
      await apiClient.logout()
      
      spinner.succeed('Successfully logged out')
      console.log(chalk.gray('Use vaultace auth login to sign in again'))
      
    } catch (error) {
      spinner.warn(`Logout completed with warnings: ${error.message}`)
    }
  })

// Status subcommand
authCommand
  .command('status')
  .description('Show authentication status')
  .action(async () => {
    const config = ConfigManager.getConfig()
    
    if (!config.auth?.accessToken) {
      console.log(chalk.gray('❌ Not logged in'))
      console.log(chalk.gray('Run vaultace auth login to authenticate'))
      return
    }
    
    const spinner = ora('Checking authentication status...').start()
    
    try {
      const apiClient = new APIClient(config)
      const userInfo = await apiClient.getCurrentUser()
      
      spinner.stop()
      
      console.log(chalk.green('✅ Authenticated'))
      console.log(`${chalk.bold('User:')} ${userInfo.email}`)
      console.log(`${chalk.bold('Role:')} ${userInfo.role}`)
      console.log(`${chalk.bold('Organization:')} ${userInfo.organization_id}`)
      console.log(`${chalk.bold('Verified:')} ${userInfo.is_verified ? '✅' : '❌'}`)
      console.log(`${chalk.bold('MFA:')} ${userInfo.mfa_enabled ? '✅' : '❌'}`)
      
      // Check token expiration
      if (config.auth.expiresAt) {
        const expiresIn = Math.max(0, config.auth.expiresAt - Date.now())
        const hours = Math.floor(expiresIn / (1000 * 60 * 60))
        const minutes = Math.floor((expiresIn % (1000 * 60 * 60)) / (1000 * 60))
        
        if (expiresIn > 0) {
          console.log(`${chalk.bold('Token expires:')} ${hours}h ${minutes}m`)
        } else {
          console.log(chalk.yellow('⚠️  Token expired - automatic refresh will occur'))
        }
      }
      
    } catch (error) {
      spinner.fail(`Authentication check failed: ${error.message}`)
      
      if (error.message.includes('Authentication required')) {
        console.log(chalk.gray('Run vaultace auth login to authenticate'))
      }
      
      process.exit(1)
    }
  })

module.exports = authCommand