/**
 * Billing Command - Subscription and billing management
 */

const { Command } = require('commander')
const chalk = require('chalk')
const ora = require('ora')
const inquirer = require('inquirer')
const { table } = require('table')
const logger = require('../utils/logger')
const APIClient = require('../services/api-client')

const billingCommand = new Command('billing')
  .description('💳 Manage subscriptions and billing')

// Show billing status
billingCommand
  .command('status')
  .description('Show current billing and subscription status')
  .action(async () => {
    const spinner = ora('Fetching billing status...').start()

    try {
      logger.command('billing status', {}, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/billing/status')

      spinner.succeed('Billing status retrieved')

      const data = response.data

      console.log(chalk.bold.green('\n💳 Billing Status\n'))

      const statusData = [
        ['Item', 'Details'],
        ['Plan', data.plan_name || 'Free'],
        ['Status', data.status || 'Unknown'],
        ['Next Billing', data.next_billing_date || 'N/A'],
        ['Amount', data.next_amount ? `$${data.next_amount}` : 'N/A'],
        ['Scans Used', `${data.scans_used || 0}/${data.scan_limit || 'Unlimited'}`],
        ['Repositories', `${data.repos_count || 0}/${data.repo_limit || 'Unlimited'}`]
      ]

      console.log(table(statusData))

      if (data.status === 'past_due') {
        console.log(chalk.red('\n⚠️  Payment past due. Please update your payment method.'))
      }

      if (data.trial_days_remaining) {
        console.log(chalk.yellow(`\n🎯 ${data.trial_days_remaining} days remaining in trial`))
      }

    } catch (error) {
      spinner.fail('Failed to fetch billing status')
      logger.error('Billing status error', { error: error.message })

      if (error.response?.status === 401) {
        console.log(chalk.yellow('\nAuthentication required. Run: vaultace auth login'))
      } else {
        console.error(chalk.red(`Error: ${error.message}`))
      }
      process.exit(1)
    }
  })

// List available plans
billingCommand
  .command('plans')
  .description('Show available subscription plans')
  .action(async () => {
    const spinner = ora('Fetching available plans...').start()

    try {
      logger.command('billing plans', {}, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/billing/plans')

      spinner.succeed('Plans retrieved')

      const plans = response.data.plans || []

      console.log(chalk.bold.blue('\n📋 Available Plans\n'))

      plans.forEach(plan => {
        console.log(chalk.bold(plan.name))
        console.log(`  Price: $${plan.price}/${plan.billing_period}`)
        console.log(`  Scans: ${plan.scan_limit || 'Unlimited'}`)
        console.log(`  Repositories: ${plan.repo_limit || 'Unlimited'}`)
        console.log(`  AI Fixes: ${plan.ai_fixes ? '✅' : '❌'}`)
        console.log(`  Team Features: ${plan.team_features ? '✅' : '❌'}`)
        console.log(`  Support: ${plan.support_level}`)
        console.log('')
      })

      console.log(chalk.gray('To upgrade: vaultace billing upgrade <plan-id>'))

    } catch (error) {
      spinner.fail('Failed to fetch plans')
      logger.error('Billing plans error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Upgrade subscription
billingCommand
  .command('upgrade')
  .description('Upgrade subscription plan')
  .argument('[plan-id]', 'plan ID to upgrade to')
  .action(async (planId) => {
    try {
      logger.command('billing upgrade', { planId }, true)

      const apiClient = new APIClient()

      // If no plan ID provided, show available plans first
      if (!planId) {
        const plansResponse = await apiClient.get('/billing/plans')
        const plans = plansResponse.data.plans || []

        const choices = plans.map(plan => ({
          name: `${plan.name} - $${plan.price}/${plan.billing_period}`,
          value: plan.id
        }))

        const { selectedPlan } = await inquirer.prompt([
          {
            type: 'list',
            name: 'selectedPlan',
            message: 'Select a plan to upgrade to:',
            choices
          }
        ])

        planId = selectedPlan
      }

      const { confirm } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'confirm',
          message: 'Confirm subscription upgrade?',
          default: false
        }
      ])

      if (!confirm) {
        console.log(chalk.yellow('Upgrade cancelled'))
        return
      }

      const spinner = ora('Processing upgrade...').start()

      const response = await apiClient.post('/billing/upgrade', {
        plan_id: planId
      })

      spinner.succeed('Subscription upgraded successfully')

      console.log(chalk.green('\n✅ Subscription upgraded!'))
      console.log(`New plan: ${response.data.plan_name}`)
      console.log(`Next billing: ${response.data.next_billing_date}`)

    } catch (error) {
      if (error.spinner) {error.spinner.fail('Upgrade failed')}
      logger.error('Billing upgrade error', { error: error.message, planId })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Payment methods
billingCommand
  .command('payment')
  .description('Manage payment methods')
  .option('--add', 'add new payment method')
  .option('--list', 'list payment methods')
  .action(async (options) => {
    try {
      logger.command('billing payment', options, true)

      const apiClient = new APIClient()

      if (options.add) {
        console.log(chalk.blue('🔗 Opening browser to add payment method...'))

        const response = await apiClient.post('/billing/payment-method/add')
        console.log(`Please visit: ${response.data.setup_url}`)
        return
      }

      if (options.list) {
        const spinner = ora('Fetching payment methods...').start()

        const response = await apiClient.get('/billing/payment-methods')
        spinner.succeed('Payment methods retrieved')

        const methods = response.data.payment_methods || []

        console.log(chalk.bold.green('\n💳 Payment Methods\n'))

        if (methods.length === 0) {
          console.log(chalk.gray('No payment methods configured'))
          console.log(chalk.blue('Add one with: vaultace billing payment --add'))
          return
        }

        methods.forEach(method => {
          const isDefault = method.is_default ? '⭐ ' : '   '
          console.log(`${isDefault}**** ${method.last4} (${method.brand}) - Expires ${method.exp_month}/${method.exp_year}`)
        })

        return
      }

      // Default: show payment command help
      console.log(chalk.blue('Payment method commands:'))
      console.log('  --add   Add new payment method')
      console.log('  --list  List existing payment methods')

    } catch (error) {
      logger.error('Billing payment error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Usage stats
billingCommand
  .command('usage')
  .description('Show current billing period usage')
  .option('--detailed', 'show detailed usage breakdown')
  .action(async (options) => {
    const spinner = ora('Fetching usage data...').start()

    try {
      logger.command('billing usage', options, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/billing/usage', {
        params: { detailed: options.detailed }
      })

      spinner.succeed('Usage data retrieved')

      const data = response.data

      console.log(chalk.bold.cyan('\n📊 Current Billing Period Usage\n'))

      const usageData = [
        ['Service', 'Used', 'Limit', 'Remaining'],
        ['Security Scans', data.scans_used || 0, data.scan_limit || 'Unlimited', data.scans_remaining || 'N/A'],
        ['AI Fixes', data.fixes_used || 0, data.fix_limit || 'Unlimited', data.fixes_remaining || 'N/A'],
        ['API Calls', data.api_calls || 0, data.api_limit || 'Unlimited', data.api_remaining || 'N/A'],
        ['Storage (MB)', data.storage_used || 0, data.storage_limit || 'Unlimited', data.storage_remaining || 'N/A']
      ]

      console.log(table(usageData))

      if (options.detailed && data.detailed_usage) {
        console.log(chalk.bold('\n📈 Daily Usage (Last 7 Days)'))
        data.detailed_usage.slice(-7).forEach(day => {
          console.log(`${day.date}: ${day.scans} scans, ${day.fixes} fixes`)
        })
      }

      // Usage warnings
      if (data.usage_warnings && data.usage_warnings.length > 0) {
        console.log(chalk.yellow('\n⚠️  Usage Warnings:'))
        data.usage_warnings.forEach(warning => {
          console.log(`  • ${warning}`)
        })
      }

    } catch (error) {
      spinner.fail('Failed to fetch usage data')
      logger.error('Billing usage error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

module.exports = billingCommand