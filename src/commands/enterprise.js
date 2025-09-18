/**
 * Enterprise Command - Enterprise features and risk quantification
 */

const { Command } = require('commander')
const chalk = require('chalk')
const ora = require('ora')
const { table } = require('table')
const fs = require('fs-extra')
const logger = require('../utils/logger')
const APIClient = require('../services/api-client')

const enterpriseCommand = new Command('enterprise')
  .description('🏢 Enterprise features and risk quantification')

// Risk quantification
enterpriseCommand
  .command('risk')
  .description('Generate enterprise risk assessment report')
  .option('--org <id>', 'organization ID')
  .option('--format <type>', 'output format (table|json|pdf)', 'table')
  .option('--output <file>', 'output file path')
  .option('--detailed', 'include detailed risk breakdown')
  .action(async (options) => {
    const spinner = ora('Generating risk assessment...').start()

    try {
      logger.command('enterprise risk', options, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/risk/assessment', {
        params: {
          organization_id: options.org,
          detailed: options.detailed
        }
      })

      spinner.succeed('Risk assessment generated')

      const risk = response.data

      if (options.format === 'json') {
        const output = JSON.stringify(risk, null, 2)

        if (options.output) {
          await fs.writeFile(options.output, output)
          console.log(chalk.green(`Risk assessment saved to ${options.output}`))
        } else {
          console.log(output)
        }
        return
      }

      console.log(chalk.bold.red('\n🏢 Enterprise Risk Assessment\n'))

      // Executive Summary
      console.log(chalk.bold.blue('📋 Executive Summary'))
      console.log(`Overall Risk Score: ${risk.overall_score}/100`)
      console.log(`Risk Level: ${risk.risk_level}`)
      console.log(`Estimated Financial Impact: $${risk.financial_impact?.toLocaleString() || 'N/A'}`)
      console.log(`Compliance Status: ${risk.compliance_status}\n`)

      // Risk Categories
      const riskData = [
        ['Category', 'Score', 'Impact', 'Likelihood', 'Mitigation'],
        ['Code Security', risk.code_security.score, risk.code_security.impact, risk.code_security.likelihood, risk.code_security.mitigation_status],
        ['Infrastructure', risk.infrastructure.score, risk.infrastructure.impact, risk.infrastructure.likelihood, risk.infrastructure.mitigation_status],
        ['Data Privacy', risk.data_privacy.score, risk.data_privacy.impact, risk.data_privacy.likelihood, risk.data_privacy.mitigation_status],
        ['Compliance', risk.compliance.score, risk.compliance.impact, risk.compliance.likelihood, risk.compliance.mitigation_status],
        ['Third Party', risk.third_party.score, risk.third_party.impact, risk.third_party.likelihood, risk.third_party.mitigation_status]
      ]

      console.log(chalk.bold.yellow('⚠️  Risk Categories'))
      console.log(table(riskData))

      // Critical Findings
      if (risk.critical_findings && risk.critical_findings.length > 0) {
        console.log(chalk.bold.red('\n🚨 Critical Findings'))
        risk.critical_findings.forEach((finding, index) => {
          console.log(`${index + 1}. ${finding.title}`)
          console.log(`   Impact: ${finding.impact} | Likelihood: ${finding.likelihood}`)
          console.log(`   Recommendation: ${finding.recommendation}\n`)
        })
      }

      // Compliance Status
      if (risk.compliance_details) {
        console.log(chalk.bold.green('\n📋 Compliance Status'))
        Object.entries(risk.compliance_details).forEach(([framework, status]) => {
          const icon = status.compliant ? '✅' : '❌'
          console.log(`${icon} ${framework}: ${status.score}% (${status.gaps} gaps)`)
        })
      }

      // Recommendations
      if (risk.recommendations && risk.recommendations.length > 0) {
        console.log(chalk.bold.blue('\n💡 Priority Recommendations'))
        risk.recommendations.slice(0, 5).forEach((rec, index) => {
          console.log(`${index + 1}. ${rec.title} (Priority: ${rec.priority})`)
          console.log(`   ${rec.description}`)
          console.log(`   Estimated ROI: ${rec.roi || 'N/A'}\n`)
        })
      }

      if (options.output) {
        const reportContent = `# Enterprise Risk Assessment Report
Generated: ${new Date().toISOString()}

## Executive Summary
- Overall Risk Score: ${risk.overall_score}/100
- Risk Level: ${risk.risk_level}
- Financial Impact: $${risk.financial_impact?.toLocaleString() || 'N/A'}

## Risk Categories
${riskData.slice(1).map(row => `- ${row[0]}: ${row[1]} (${row[2]} impact)`).join('\n')}

## Critical Findings
${risk.critical_findings?.map((f, i) => `${i+1}. ${f.title}\n   ${f.recommendation}`).join('\n\n') || 'None'}
`

        await fs.writeFile(options.output, reportContent)
        console.log(chalk.green(`\nDetailed report saved to ${options.output}`))
      }

    } catch (error) {
      spinner.fail('Failed to generate risk assessment')
      logger.error('Enterprise risk error', { error: error.message })

      if (error.response?.status === 403) {
        console.log(chalk.red('\nEnterprise features require enterprise subscription'))
      } else {
        console.error(chalk.red(`Error: ${error.message}`))
      }
      process.exit(1)
    }
  })

// Compliance audit
enterpriseCommand
  .command('compliance')
  .description('Run compliance audit against frameworks')
  .option('--framework <name>', 'compliance framework (SOC2|ISO27001|GDPR|HIPAA)', 'SOC2')
  .option('--org <id>', 'organization ID')
  .option('--remediation', 'include remediation steps')
  .action(async (options) => {
    const spinner = ora(`Running ${options.framework} compliance audit...`).start()

    try {
      logger.command('enterprise compliance', options, true)

      const apiClient = new APIClient()
      const response = await apiClient.post('/enterprise/compliance/audit', {
        framework: options.framework,
        organization_id: options.org,
        include_remediation: options.remediation
      })

      spinner.succeed('Compliance audit completed')

      const audit = response.data

      console.log(chalk.bold.blue(`\n📋 ${options.framework} Compliance Audit\n`))

      const summaryData = [
        ['Metric', 'Value'],
        ['Overall Score', `${audit.score}%`],
        ['Compliant Controls', `${audit.compliant_controls}/${audit.total_controls}`],
        ['Critical Gaps', audit.critical_gaps || 0],
        ['Medium Gaps', audit.medium_gaps || 0],
        ['Low Priority Gaps', audit.low_gaps || 0]
      ]

      console.log(table(summaryData))

      // Control Categories
      if (audit.categories) {
        console.log(chalk.bold.yellow('\n📊 Control Categories'))
        Object.entries(audit.categories).forEach(([category, data]) => {
          const status = data.compliant ? '✅' : '❌'
          console.log(`${status} ${category}: ${data.score}% (${data.gaps} gaps)`)
        })
      }

      // Gap Analysis
      if (audit.gaps && audit.gaps.length > 0) {
        console.log(chalk.bold.red('\n⚠️  Compliance Gaps'))
        audit.gaps.slice(0, 10).forEach((gap, index) => {
          const priority = gap.priority === 'critical' ? '🔴' :
            gap.priority === 'medium' ? '🟡' : '🟢'
          console.log(`${priority} ${gap.control_id}: ${gap.description}`)

          if (options.remediation && gap.remediation) {
            console.log(`   💡 ${gap.remediation}\n`)
          }
        })
      }

      // Certification readiness
      if (audit.certification_readiness) {
        console.log(chalk.bold.green('\n🏆 Certification Readiness'))
        console.log(`Ready for certification: ${audit.certification_readiness.ready ? 'Yes' : 'No'}`)
        console.log(`Estimated timeline: ${audit.certification_readiness.timeline || 'N/A'}`)
        console.log(`Remaining effort: ${audit.certification_readiness.effort || 'N/A'}`)
      }

    } catch (error) {
      spinner.fail('Compliance audit failed')
      logger.error('Enterprise compliance error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Security maturity assessment
enterpriseCommand
  .command('maturity')
  .description('Assess security maturity level')
  .option('--org <id>', 'organization ID')
  .option('--benchmark', 'compare against industry benchmarks')
  .action(async (options) => {
    const spinner = ora('Assessing security maturity...').start()

    try {
      logger.command('enterprise maturity', options, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/enterprise/maturity', {
        params: {
          organization_id: options.org,
          benchmark: options.benchmark
        }
      })

      spinner.succeed('Security maturity assessed')

      const maturity = response.data

      console.log(chalk.bold.purple('\n🎯 Security Maturity Assessment\n'))

      console.log(`Current Maturity Level: ${maturity.level} (${maturity.score}/5)`)
      console.log(`Industry Percentile: ${maturity.percentile || 'N/A'}`)
      console.log(`Next Level Target: ${maturity.next_level}\n`)

      // Capability Areas
      const capabilityData = [
        ['Capability', 'Current', 'Target', 'Gap'],
        ['Governance', maturity.governance.current, maturity.governance.target, maturity.governance.gap],
        ['Risk Management', maturity.risk_management.current, maturity.risk_management.target, maturity.risk_management.gap],
        ['Asset Management', maturity.asset_management.current, maturity.asset_management.target, maturity.asset_management.gap],
        ['Access Control', maturity.access_control.current, maturity.access_control.target, maturity.access_control.gap],
        ['Incident Response', maturity.incident_response.current, maturity.incident_response.target, maturity.incident_response.gap],
        ['Monitoring', maturity.monitoring.current, maturity.monitoring.target, maturity.monitoring.gap]
      ]

      console.log(chalk.bold.blue('📊 Capability Maturity'))
      console.log(table(capabilityData))

      // Improvement roadmap
      if (maturity.roadmap && maturity.roadmap.length > 0) {
        console.log(chalk.bold.green('\n🗺️  Improvement Roadmap'))
        maturity.roadmap.forEach((milestone, index) => {
          console.log(`${index + 1}. ${milestone.title} (${milestone.timeline})`)
          console.log(`   Effort: ${milestone.effort} | Impact: ${milestone.impact}`)
          console.log(`   ${milestone.description}\n`)
        })
      }

      // Benchmarking
      if (options.benchmark && maturity.benchmark) {
        console.log(chalk.bold.cyan('\n📈 Industry Benchmarks'))
        console.log(`Your Score: ${maturity.score}/5`)
        console.log(`Industry Average: ${maturity.benchmark.average}/5`)
        console.log(`Top Quartile: ${maturity.benchmark.top_quartile}/5`)
        console.log(`Best in Class: ${maturity.benchmark.best_in_class}/5`)
      }

    } catch (error) {
      spinner.fail('Failed to assess security maturity')
      logger.error('Enterprise maturity error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Executive dashboard
enterpriseCommand
  .command('dashboard')
  .description('Generate executive security dashboard')
  .option('--org <id>', 'organization ID')
  .option('--period <timeframe>', 'reporting period (week|month|quarter)', 'month')
  .action(async (options) => {
    const spinner = ora('Generating executive dashboard...').start()

    try {
      logger.command('enterprise dashboard', options, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/enterprise/dashboard', {
        params: {
          organization_id: options.org,
          period: options.period
        }
      })

      spinner.succeed('Executive dashboard generated')

      const dashboard = response.data

      console.log(chalk.bold.blue('\n🏢 Executive Security Dashboard\n'))

      // Key Metrics
      const metricsData = [
        ['Metric', 'Current', 'Previous', 'Trend'],
        ['Security Score', dashboard.security_score.current, dashboard.security_score.previous, dashboard.security_score.trend],
        ['Active Vulnerabilities', dashboard.vulnerabilities.active, dashboard.vulnerabilities.previous, dashboard.vulnerabilities.trend],
        ['Mean Time to Fix', dashboard.mttr.current + ' hours', dashboard.mttr.previous + ' hours', dashboard.mttr.trend],
        ['Compliance Score', dashboard.compliance.current + '%', dashboard.compliance.previous + '%', dashboard.compliance.trend],
        ['Team Productivity', dashboard.productivity.current, dashboard.productivity.previous, dashboard.productivity.trend]
      ]

      console.log(chalk.bold.green('📊 Key Security Metrics'))
      console.log(table(metricsData))

      // Risk Summary
      if (dashboard.risk_summary) {
        console.log(chalk.bold.red('\n⚠️  Risk Summary'))
        console.log(`High Risk Issues: ${dashboard.risk_summary.high}`)
        console.log(`Medium Risk Issues: ${dashboard.risk_summary.medium}`)
        console.log(`Low Risk Issues: ${dashboard.risk_summary.low}`)
        console.log(`Total Risk Exposure: $${dashboard.risk_summary.financial_exposure?.toLocaleString() || 'N/A'}`)
      }

      // Security Investments
      if (dashboard.investments) {
        console.log(chalk.bold.blue('\n💰 Security Investments'))
        console.log(`Monthly Spend: $${dashboard.investments.monthly_spend?.toLocaleString() || 'N/A'}`)
        console.log(`ROI: ${dashboard.investments.roi || 'N/A'}%`)
        console.log(`Cost per Vulnerability Fixed: $${dashboard.investments.cost_per_fix || 'N/A'}`)
      }

      // Achievements
      if (dashboard.achievements && dashboard.achievements.length > 0) {
        console.log(chalk.bold.green('\n🎉 Recent Achievements'))
        dashboard.achievements.slice(0, 3).forEach(achievement => {
          console.log(`✅ ${achievement.title} (${achievement.date})`)
        })
      }

    } catch (error) {
      spinner.fail('Failed to generate executive dashboard')
      logger.error('Enterprise dashboard error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

module.exports = enterpriseCommand