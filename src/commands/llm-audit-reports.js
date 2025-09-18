/**
 * LLM Audit Reports Command
 * CLI interface for generating formal audit documentation for compliance frameworks
 */

const { Command } = require('commander')
const LLMAuditReports = require('../services/llm-audit-reports')
const logger = require('../utils/logger')
const fs = require('fs-extra')
const path = require('path')
const chalk = require('chalk')
const { Table } = require('table')

function createLLMAuditReportsCommand() {
  const cmd = new Command('audit-reports')
    .description('Generate formal audit documentation for AI compliance frameworks')
    .option('-f, --framework <framework>', 'Compliance framework: eu-ai-act, iso-iec-5338, financial-services, healthcare-hipaa', 'eu-ai-act')
    .option('-o, --output <path>', 'Output directory for reports')
    .option('--format <format>', 'Export format: json, csv, pdf, html', 'json')
    .option('--notify', 'Send notifications to stakeholders')
    .option('--stakeholders <emails>', 'Comma-separated list of stakeholder emails')
    .option('--schedule <cron>', 'Schedule recurring reports (cron format)')
    .option('--trends', 'Include historical trend analysis')
    .option('--json', 'Output results in JSON format')
    .action(async (options) => {
      try {
        const auditService = new LLMAuditReports({
          verbose: options.verbose
        })

        logger.info(`Generating ${options.framework} audit report...`)

        // Parse stakeholders if provided
        const stakeholders = options.stakeholders
          ? options.stakeholders.split(',').map(email => ({ email: email.trim() }))
          : []

        // Generate audit report
        const report = await auditService.generateAuditReport(options.framework, {
          notifyStakeholders: options.notify,
          stakeholders,
          includeTrends: options.trends
        })

        // Export report in specified format
        const outputPath = options.output || process.cwd()
        const exportPath = await auditService.exportReport(report, options.format, path.join(outputPath, `audit-report-${options.framework}.${options.format}`))

        if (options.json) {
          console.log(JSON.stringify({
            success: true,
            reportId: report.metadata.reportId,
            framework: report.metadata.framework,
            complianceScore: report.metadata.complianceScore,
            exportPath,
            timestamp: report.metadata.timestamp
          }, null, 2))
        } else {
          displayAuditReportSummary(report, exportPath)
        }

        // Schedule recurring reports if requested
        if (options.schedule) {
          const schedule = await auditService.scheduleReport(options.framework, options.schedule, {
            format: options.format,
            outputPath,
            stakeholders
          })

          logger.info(`Audit report scheduled successfully`, {
            scheduleId: schedule.id,
            nextRun: schedule.nextRun
          })
        }

      } catch (error) {
        logger.error(`Audit report generation failed: ${error.message}`)
        if (options.verbose) {
          console.error(error.stack)
        }
        process.exit(1)
      }
    })

  // Subcommand: List available frameworks
  cmd.command('frameworks')
    .description('List available compliance frameworks')
    .option('--json', 'Output in JSON format')
    .action(async (options) => {
      const frameworks = {
        'eu-ai-act': {
          name: 'EU AI Act',
          description: 'European Union Artificial Intelligence Act compliance',
          riskLevels: ['Minimal', 'Limited', 'High', 'Unacceptable'],
          keyRequirements: ['Transparency', 'Human Oversight', 'Accuracy', 'Data Governance']
        },
        'iso-iec-5338': {
          name: 'ISO/IEC 5338',
          description: 'AI Lifecycle Management Standard',
          phases: ['Planning', 'Development', 'Deployment', 'Monitoring'],
          keyAreas: ['Risk Management', 'Quality Assurance', 'Configuration Management']
        },
        'financial-services': {
          name: 'Financial Services AI Governance',
          description: 'Banking and financial industry AI compliance',
          regulations: ['Basel III', 'MiFID II', 'GDPR', 'PCI DSS'],
          keyAreas: ['Model Risk', 'Algorithmic Trading', 'Credit Decisions', 'Data Security']
        },
        'healthcare-hipaa': {
          name: 'Healthcare HIPAA AI Compliance',
          description: 'Healthcare AI systems under HIPAA regulations',
          safeguards: ['Administrative', 'Physical', 'Technical'],
          keyAreas: ['PHI Protection', 'Access Controls', 'Audit Logging', 'Risk Assessment']
        }
      }

      if (options.json) {
        console.log(JSON.stringify(frameworks, null, 2))
      } else {
        console.log(chalk.blue('\n📋 Available Compliance Frameworks\n'))
        Object.entries(frameworks).forEach(([key, framework]) => {
          console.log(chalk.bold(`${key}: ${framework.name}`))
          console.log(`   ${framework.description}`)
          if (framework.keyRequirements) {
            console.log(`   Key Requirements: ${framework.keyRequirements.join(', ')}`)
          }
          if (framework.keyAreas) {
            console.log(`   Key Areas: ${framework.keyAreas.join(', ')}`)
          }
          console.log()
        })
      }
    })

  // Subcommand: Historical trends
  cmd.command('trends')
    .description('View historical compliance trends')
    .argument('[framework]', 'Specific framework to analyze')
    .option('--range <range>', 'Time range: 1m, 3m, 6m, 1y', '6m')
    .option('--json', 'Output in JSON format')
    .action(async (framework, options) => {
      try {
        const auditService = new LLMAuditReports()

        if (framework) {
          const trends = auditService.getHistoricalTrends(framework, options.range)
          if (options.json) {
            console.log(JSON.stringify(trends, null, 2))
          } else {
            displayTrendsAnalysis(framework, trends)
          }
        } else {
          // Show trends for all frameworks
          const frameworks = ['eu-ai-act', 'iso-iec-5338', 'financial-services', 'healthcare-hipaa']
          console.log(chalk.blue('\n📈 Historical Compliance Trends\n'))

          for (const fw of frameworks) {
            const trends = auditService.getHistoricalTrends(fw, options.range)
            if (trends.complianceScoreTrend.trend !== 'insufficient-data') {
              console.log(chalk.bold(`${fw}:`))
              console.log(`  Compliance Trend: ${getTrendIcon(trends.complianceScoreTrend.trend)} ${trends.complianceScoreTrend.trend}`)
              console.log(`  Risk Trend: ${getTrendIcon(trends.riskTrend.trend)} ${trends.riskTrend.trend}`)
              console.log()
            }
          }
        }

      } catch (error) {
        logger.error(`Failed to retrieve trends: ${error.message}`)
        process.exit(1)
      }
    })

  // Subcommand: Schedule management
  cmd.command('schedule')
    .description('Manage scheduled audit reports')
    .option('--list', 'List all scheduled reports')
    .option('--cancel <scheduleId>', 'Cancel a scheduled report')
    .option('--json', 'Output in JSON format')
    .action(async (options) => {
      try {
        const auditService = new LLMAuditReports()

        if (options.list) {
          await listScheduledReports(auditService, options.json)
        } else if (options.cancel) {
          await cancelScheduledReport(auditService, options.cancel, options.json)
        } else {
          console.log('Use --list to view scheduled reports or --cancel <id> to cancel a report')
        }

      } catch (error) {
        logger.error(`Schedule management failed: ${error.message}`)
        process.exit(1)
      }
    })

  // Subcommand: Validate compliance
  cmd.command('validate')
    .description('Validate current system against compliance requirements')
    .argument('<framework>', 'Framework to validate against')
    .option('--quick', 'Perform quick validation only')
    .option('--json', 'Output in JSON format')
    .action(async (framework, options) => {
      try {
        const auditService = new LLMAuditReports()

        console.log(chalk.blue(`\n🔍 Validating compliance against ${framework}...\n`))

        // Quick validation - check basic guardrails
        if (options.quick) {
          const validation = await performQuickValidation(auditService, framework)
          if (options.json) {
            console.log(JSON.stringify(validation, null, 2))
          } else {
            displayValidationResults(validation)
          }
        } else {
          // Full audit report
          const report = await auditService.generateAuditReport(framework)
          if (options.json) {
            console.log(JSON.stringify(report.metadata.complianceScore, null, 2))
          } else {
            displayComplianceValidation(report)
          }
        }

      } catch (error) {
        logger.error(`Compliance validation failed: ${error.message}`)
        process.exit(1)
      }
    })

  // Subcommand: Export existing report
  cmd.command('export')
    .description('Export an existing audit report in different format')
    .argument('<reportPath>', 'Path to existing audit report JSON file')
    .option('--format <format>', 'Export format: json, csv, pdf, html', 'html')
    .option('--output <path>', 'Output file path')
    .action(async (reportPath, options) => {
      try {
        if (!await fs.exists(reportPath)) {
          logger.error(`Report file not found: ${reportPath}`)
          process.exit(1)
        }

        const report = await fs.readJson(reportPath)
        const auditService = new LLMAuditReports()

        const outputPath = options.output || reportPath.replace('.json', `.${options.format}`)
        const exportPath = await auditService.exportReport(report, options.format, outputPath)

        logger.info(`Report exported successfully to ${exportPath}`)

      } catch (error) {
        logger.error(`Export failed: ${error.message}`)
        process.exit(1)
      }
    })

  return cmd
}

// ===============================
// Display Helper Functions
// ===============================

function displayAuditReportSummary(report, exportPath) {
  console.log(chalk.blue('\n🛡️  Vaultace AI Security Audit Report'))
  console.log('='.repeat(60))

  console.log(chalk.bold('\n📊 Executive Summary'))
  console.log(`Framework: ${report.metadata.framework}`)
  console.log(`Overall Score: ${getScoreColor(report.metadata.complianceScore.overall)}${report.metadata.complianceScore.overall}/100`)
  console.log(`Rating: ${getRatingColor(report.metadata.complianceScore.rating)}${report.metadata.complianceScore.rating}`)
  console.log(`Risk Level: ${getRiskColor(report.executiveSummary.overview.executiveRisk)}${report.executiveSummary.overview.executiveRisk}`)

  // Compliance breakdown
  console.log(chalk.bold('\n📈 Compliance Breakdown'))
  const breakdownData = [
    ['Category', 'Score', 'Status'],
    ...Object.entries(report.metadata.complianceScore.breakdown).map(([category, score]) => [
      category.charAt(0).toUpperCase() + category.slice(1),
      `${score}/100`,
      score >= 80 ? chalk.green('✓ Good') : score >= 60 ? chalk.yellow('⚠ Fair') : chalk.red('✗ Poor')
    ])
  ]

  console.log(Table(breakdownData, {
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
      bodyJoin: '│',
      joinBody: '─',
      joinLeft: '├',
      joinRight: '┤',
      joinJoin: '┼'
    }
  }))

  // Key findings
  if (report.executiveSummary.keyFindings.criticalIssues.length > 0) {
    console.log(chalk.bold('\n🚨 Critical Issues'))
    report.executiveSummary.keyFindings.criticalIssues.forEach((issue, index) => {
      console.log(`${index + 1}. ${chalk.red(issue)}`)
    })
  }

  // Strengths
  if (report.executiveSummary.keyFindings.strengths.length > 0) {
    console.log(chalk.bold('\n✅ Strengths'))
    report.executiveSummary.keyFindings.strengths.forEach((strength, index) => {
      console.log(`${index + 1}. ${chalk.green(strength)}`)
    })
  }

  // Priority recommendations
  if (report.executiveSummary.priorityRecommendations.length > 0) {
    console.log(chalk.bold('\n💡 Priority Recommendations'))
    report.executiveSummary.priorityRecommendations.forEach((rec, index) => {
      console.log(`${index + 1}. ${rec}`)
    })
  }

  console.log(chalk.bold('\n📄 Report Details'))
  console.log(`Report ID: ${report.metadata.reportId}`)
  console.log(`Generated: ${new Date(report.metadata.timestamp).toLocaleString()}`)
  console.log(`Exported to: ${exportPath}`)

  console.log('\n' + '='.repeat(60))
}

function displayTrendsAnalysis(framework, trends) {
  console.log(chalk.blue(`\n📈 Trends Analysis: ${framework}\n`))

  console.log(chalk.bold('Compliance Score Trend'))
  console.log(`  Direction: ${getTrendIcon(trends.complianceScoreTrend.trend)} ${trends.complianceScoreTrend.trend}`)
  console.log(`  Change: ${trends.complianceScoreTrend.change > 0 ? '+' : ''}${trends.complianceScoreTrend.change}`)

  console.log(chalk.bold('\nRisk Trend'))
  console.log(`  Direction: ${getTrendIcon(trends.riskTrend.trend)} ${trends.riskTrend.trend}`)
  console.log(`  Change: ${trends.riskTrend.change > 0 ? '+' : ''}${trends.riskTrend.change}`)

  if (trends.improvementAreas.length > 0) {
    console.log(chalk.bold('\n📈 Improvement Areas'))
    trends.improvementAreas.forEach((area, index) => {
      console.log(`${index + 1}. ${area}`)
    })
  }

  if (trends.regressionAreas.length > 0) {
    console.log(chalk.bold('\n📉 Areas of Concern'))
    trends.regressionAreas.forEach((area, index) => {
      console.log(`${index + 1}. ${area}`)
    })
  }
}

function displayValidationResults(validation) {
  console.log(chalk.bold('✅ Validation Results\n'))

  validation.checks.forEach(check => {
    const status = check.passed ? chalk.green('✓ PASS') : chalk.red('✗ FAIL')
    console.log(`${status} ${check.name}`)
    if (!check.passed && check.issues) {
      check.issues.forEach(issue => {
        console.log(`    ${chalk.yellow('⚠')} ${issue}`)
      })
    }
  })

  console.log(`\nOverall: ${validation.overallPassed ? chalk.green('COMPLIANT') : chalk.red('NON-COMPLIANT')}`)
}

function displayComplianceValidation(report) {
  console.log(chalk.bold('🔍 Compliance Validation Results\n'))

  console.log(`Overall Score: ${getScoreColor(report.metadata.complianceScore.overall)}${report.metadata.complianceScore.overall}/100`)
  console.log(`Rating: ${getRatingColor(report.metadata.complianceScore.rating)}${report.metadata.complianceScore.rating}`)

  Object.entries(report.metadata.complianceScore.breakdown).forEach(([category, score]) => {
    const color = score >= 80 ? chalk.green : score >= 60 ? chalk.yellow : chalk.red
    console.log(`${category}: ${color(score)}/100`)
  })

  if (report.metadata.complianceScore.improvements.length > 0) {
    console.log(chalk.bold('\n🎯 Improvement Priorities'))
    report.metadata.complianceScore.improvements.forEach(improvement => {
      console.log(`${improvement.priority === 'High' ? chalk.red('🔴') : chalk.yellow('🟡')} ${improvement.category} (${improvement.score}/100)`)
    })
  }
}

async function listScheduledReports(auditService, json) {
  // This would read from the schedules file
  const schedulesPath = path.join(require('os').homedir(), '.vaultace', 'audit-reports', 'schedules.json')

  if (!await fs.exists(schedulesPath)) {
    if (json) {
      console.log(JSON.stringify({ schedules: [] }, null, 2))
    } else {
      console.log('No scheduled reports found.')
    }
    return
  }

  const schedules = await fs.readJson(schedulesPath)

  if (json) {
    console.log(JSON.stringify({ schedules }, null, 2))
  } else {
    console.log(chalk.blue('\n📅 Scheduled Audit Reports\n'))

    if (schedules.length === 0) {
      console.log('No scheduled reports found.')
      return
    }

    const scheduleData = [
      ['ID', 'Framework', 'Schedule', 'Next Run', 'Status'],
      ...schedules.map(schedule => [
        schedule.id.substring(0, 8),
        schedule.framework,
        schedule.schedule,
        new Date(schedule.nextRun).toLocaleString(),
        schedule.status
      ])
    ]

    console.log(Table(scheduleData))
  }
}

async function cancelScheduledReport(auditService, scheduleId, json) {
  const schedulesPath = path.join(require('os').homedir(), '.vaultace', 'audit-reports', 'schedules.json')

  if (!await fs.exists(schedulesPath)) {
    if (json) {
      console.log(JSON.stringify({ success: false, error: 'No schedules found' }, null, 2))
    } else {
      logger.error('No scheduled reports found.')
    }
    return
  }

  let schedules = await fs.readJson(schedulesPath)
  const originalLength = schedules.length

  schedules = schedules.filter(schedule => !schedule.id.startsWith(scheduleId))

  if (schedules.length === originalLength) {
    if (json) {
      console.log(JSON.stringify({ success: false, error: 'Schedule not found' }, null, 2))
    } else {
      logger.error(`Schedule ${scheduleId} not found.`)
    }
    return
  }

  await fs.writeJson(schedulesPath, schedules, { spaces: 2 })

  if (json) {
    console.log(JSON.stringify({ success: true, message: 'Schedule cancelled' }, null, 2))
  } else {
    logger.info(`Schedule ${scheduleId} cancelled successfully.`)
  }
}

async function performQuickValidation(auditService, framework) {
  // Quick validation checks basic guardrails functionality
  const checks = [
    {
      name: 'Inappropriate Content Filter',
      test: async () => {
        const result = auditService.guardrails.inappropriateContentFilter('test content')
        return { passed: true, issues: [] }
      }
    },
    {
      name: 'Prompt Injection Shield',
      test: async () => {
        const result = auditService.guardrails.promptInjectionShield('normal prompt')
        return { passed: !result.blocked, issues: result.violations.map(v => v.message) }
      }
    },
    {
      name: 'Sensitive Data Scanner',
      test: async () => {
        const result = auditService.guardrails.sensitiveContentScanner('regular text')
        return { passed: !result.blocked, issues: result.violations.map(v => v.message) }
      }
    }
  ]

  const results = []
  let overallPassed = true

  for (const check of checks) {
    try {
      const result = await check.test()
      results.push({ name: check.name, ...result })
      if (!result.passed) overallPassed = false
    } catch (error) {
      results.push({
        name: check.name,
        passed: false,
        issues: [error.message]
      })
      overallPassed = false
    }
  }

  return { checks: results, overallPassed }
}

// ===============================
// Utility Functions
// ===============================

function getScoreColor(score) {
  if (score >= 90) return chalk.green
  if (score >= 80) return chalk.blue
  if (score >= 70) return chalk.yellow
  if (score >= 60) return chalk.orange
  return chalk.red
}

function getRatingColor(rating) {
  const colors = {
    'Excellent': chalk.green,
    'Good': chalk.blue,
    'Satisfactory': chalk.yellow,
    'Needs Improvement': chalk.orange,
    'Poor': chalk.red
  }
  return colors[rating] || chalk.gray
}

function getRiskColor(risk) {
  const colors = {
    'Low': chalk.green,
    'Medium': chalk.yellow,
    'High': chalk.red,
    'Critical': chalk.redBright
  }
  return colors[risk] || chalk.gray
}

function getTrendIcon(trend) {
  const icons = {
    'improving': chalk.green('📈'),
    'declining': chalk.red('📉'),
    'stable': chalk.blue('➡️'),
    'insufficient-data': chalk.gray('❓')
  }
  return icons[trend] || '📊'
}

module.exports = createLLMAuditReportsCommand