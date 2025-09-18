/**
 * Analytics Command - Security analytics and metrics
 */

const { Command } = require('commander')
const chalk = require('chalk')
const ora = require('ora')
const { table } = require('table')
const logger = require('../utils/logger')
const APIClient = require('../services/api-client')

const analyticsCommand = new Command('analytics')
  .description('📊 View security analytics and metrics')

// Dashboard analytics
analyticsCommand
  .command('dashboard')
  .description('Show security dashboard metrics')
  .option('--org <id>', 'organization ID')
  .option('--timeframe <period>', 'time period (7d|30d|90d|1y)', '30d')
  .option('--format <type>', 'output format (table|json)', 'table')
  .action(async (options) => {
    const spinner = ora('Fetching dashboard analytics...').start()

    try {
      logger.command('analytics dashboard', options, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/analytics/dashboard', {
        params: {
          organization_id: options.org,
          timeframe: options.timeframe
        }
      })

      spinner.succeed('Analytics retrieved successfully')

      const data = response.data

      if (options.format === 'json') {
        console.log(JSON.stringify(data, null, 2))
        return
      }

      // Display formatted dashboard
      console.log(chalk.bold.cyan('\n🏢 Security Dashboard\n'))

      const overviewData = [
        ['Metric', 'Value', 'Trend'],
        ['Total Vulnerabilities', data.total_vulnerabilities || 0, data.vuln_trend || 'N/A'],
        ['Critical Issues', data.critical_count || 0, data.critical_trend || 'N/A'],
        ['Fixed This Period', data.fixed_count || 0, data.fixed_trend || 'N/A'],
        ['Security Score', data.security_score || 'N/A', data.score_trend || 'N/A'],
        ['Scan Coverage', `${data.scan_coverage || 0}%`, data.coverage_trend || 'N/A']
      ]

      console.log(table(overviewData, {
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

      if (data.recent_scans && data.recent_scans.length > 0) {
        console.log(chalk.bold('\n📈 Recent Scans'))
        data.recent_scans.slice(0, 5).forEach(scan => {
          const status = scan.status === 'completed' ? '✅' : '⏳'
          console.log(`  ${status} ${scan.repository} - ${scan.vulnerabilities_found} issues (${scan.created_at})`)
        })
      }

    } catch (error) {
      spinner.fail('Failed to fetch analytics')
      logger.error('Analytics dashboard error', { error: error.message })

      if (error.response?.status === 401) {
        console.log(chalk.yellow('\nAuthentication required. Run: vaultace auth login'))
      } else {
        console.error(chalk.red(`Error: ${error.message}`))
      }
      process.exit(1)
    }
  })

// Risk metrics
analyticsCommand
  .command('risk')
  .description('Show risk assessment metrics')
  .option('--org <id>', 'organization ID')
  .option('--detailed', 'show detailed risk breakdown')
  .action(async (options) => {
    const spinner = ora('Calculating risk metrics...').start()

    try {
      logger.command('analytics risk', options, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/analytics/risk', {
        params: {
          organization_id: options.org,
          detailed: options.detailed
        }
      })

      spinner.succeed('Risk metrics calculated')

      const data = response.data

      console.log(chalk.bold.red('\n⚠️  Risk Assessment\n'))

      const riskData = [
        ['Risk Category', 'Score', 'Level'],
        ['Overall Risk', data.overall_risk || 'N/A', data.risk_level || 'Unknown'],
        ['Code Quality', data.code_quality_risk || 'N/A', data.code_quality_level || 'Unknown'],
        ['Infrastructure', data.infrastructure_risk || 'N/A', data.infrastructure_level || 'Unknown'],
        ['Dependencies', data.dependency_risk || 'N/A', data.dependency_level || 'Unknown'],
        ['Compliance', data.compliance_risk || 'N/A', data.compliance_level || 'Unknown']
      ]

      console.log(table(riskData))

      if (options.detailed && data.risk_factors) {
        console.log(chalk.bold('\n🔍 Risk Factors'))
        data.risk_factors.forEach(factor => {
          const impact = factor.impact === 'high' ? '🔴' :
            factor.impact === 'medium' ? '🟡' : '🟢'
          console.log(`  ${impact} ${factor.description} (Impact: ${factor.impact})`)
        })
      }

    } catch (error) {
      spinner.fail('Failed to calculate risk metrics')
      logger.error('Risk analytics error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Trends analysis
analyticsCommand
  .command('trends')
  .description('Show security trends over time')
  .option('--timeframe <period>', 'time period (30d|90d|1y)', '90d')
  .option('--metric <type>', 'metric type (vulnerabilities|fixes|scans)', 'vulnerabilities')
  .action(async (options) => {
    const spinner = ora('Analyzing trends...').start()

    try {
      logger.command('analytics trends', options, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/analytics/trends', {
        params: {
          timeframe: options.timeframe,
          metric: options.metric
        }
      })

      spinner.succeed('Trends analyzed')

      const data = response.data

      console.log(chalk.bold.blue(`\n📈 ${options.metric.toUpperCase()} Trends (${options.timeframe})\n`))

      if (data.trend_data && data.trend_data.length > 0) {
        data.trend_data.forEach(point => {
          const bar = '█'.repeat(Math.floor(point.value / (data.max_value || 1) * 20))
          console.log(`${point.date}: ${bar} ${point.value}`)
        })

        console.log(`\nTrend: ${data.trend_direction} (${data.trend_percentage}%)`)
      } else {
        console.log('No trend data available for the selected period.')
      }

    } catch (error) {
      spinner.fail('Failed to analyze trends')
      logger.error('Trends analytics error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

module.exports = analyticsCommand