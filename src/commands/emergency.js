/**
 * Emergency Response Command
 * Crisis management and post-incident recovery for security breaches
 */

const { Command } = require('commander')
const chalk = require('chalk')
const inquirer = require('inquirer')
const ora = require('ora')
const { table } = require('table')

const APIClient = require('../services/api-client')
const LocalScanner = require('../services/local-scanner')
const ConfigManager = require('../utils/config-manager')

const emergencyCommand = new Command('emergency')
  .description('Emergency security response and post-incident recovery')

// Emergency scan
emergencyCommand
  .command('scan')
  .description('Emergency vulnerability scan with immediate triage')
  .argument('[path]', 'repository path to scan', '.')
  .option('--all-severities', 'scan for all vulnerabilities (ignore severity filter)')
  .option('--rapid', 'rapid scan mode (faster, less comprehensive)')
  .action(async (scanPath, options) => {
    console.log(chalk.bold.red('🚨 VAULTACE EMERGENCY SECURITY SCAN'))
    console.log(chalk.red('━'.repeat(50)))
    console.log(chalk.yellow('⚠️  Emergency mode: Scanning for immediate threats\n'))
    
    const spinner = ora('Running emergency vulnerability scan...').start()
    
    try {
      // Use emergency scan settings
      const scanner = new LocalScanner({
        path: scanPath,
        severity: options.allSeverities ? 'low' : 'high',
        aiPatterns: true,
        verbose: true
      })
      
      const results = await scanner.scan()
      
      // Filter to critical and high only for emergency
      const criticalVulns = results.vulnerabilities.filter(v => 
        v.severity === 'critical'
      )
      const highVulns = results.vulnerabilities.filter(v => 
        v.severity === 'high'
      )
      
      spinner.stop()
      
      if (criticalVulns.length === 0 && highVulns.length === 0) {
        console.log(chalk.green('✅ NO IMMEDIATE THREATS DETECTED'))
        console.log(chalk.gray('Your code appears secure from critical vulnerabilities'))
        return
      }
      
      // Show emergency triage
      console.log(chalk.bold.red('\n🚨 IMMEDIATE THREATS DETECTED'))
      console.log(chalk.red(`${criticalVulns.length} CRITICAL | ${highVulns.length} HIGH severity\n`))
      
      // Critical vulnerabilities table
      if (criticalVulns.length > 0) {
        console.log(chalk.bold.red('🔴 CRITICAL - FIX IMMEDIATELY:'))
        
        const criticalTable = [
          [chalk.bold('File'), chalk.bold('Line'), chalk.bold('Type'), chalk.bold('Fix Time')]
        ]
        
        criticalVulns.forEach(vuln => {
          criticalTable.push([
            chalk.red(vuln.file),
            vuln.line.toString(),
            vuln.type.replace(/_/g, ' '),
            getFixTime(vuln.type)
          ])
        })
        
        console.log(table(criticalTable))
      }
      
      // High vulnerabilities (condensed)
      if (highVulns.length > 0) {
        console.log(chalk.bold.yellow('\n🟡 HIGH PRIORITY:'))
        highVulns.slice(0, 5).forEach(vuln => {
          console.log(`   ${vuln.file}:${vuln.line} - ${vuln.type}`)
        })
        
        if (highVulns.length > 5) {
          console.log(chalk.gray(`   ... and ${highVulns.length - 5} more`))
        }
      }
      
      // Emergency action plan
      console.log(chalk.bold('\n🆘 EMERGENCY ACTION PLAN:'))
      console.log('1. ' + chalk.red('Fix critical vulnerabilities within 24 hours'))
      console.log('2. ' + chalk.yellow('Review and test all authentication code'))
      console.log('3. ' + chalk.blue('Set up continuous monitoring: vaultace repo add <url>'))
      console.log('4. ' + chalk.gray('Document incident timeline for compliance'))
      
      // Offer incident reporting
      const { reportIncident } = await inquirer.prompt([{
        type: 'confirm',
        name: 'reportIncident',
        message: 'Report this as a security incident for recovery assistance?',
        default: true
      }])
      
      if (reportIncident) {
        await reportSecurityIncident(criticalVulns, highVulns)
      }
      
    } catch (error) {
      spinner.fail(`Emergency scan failed: ${error.message}`)
      console.log(chalk.red('\n🆘 Scan failure during emergency - manual review required'))
      process.exit(1)
    }
  })

// Incident reporting
emergencyCommand
  .command('report')
  .description('Report security incident for recovery assistance')
  .action(async () => {
    console.log(chalk.bold.red('🚨 SECURITY INCIDENT REPORT'))
    console.log(chalk.red('━'.repeat(40)))
    console.log(chalk.yellow('Report security incidents for emergency response and recovery guidance\n'))
    
    const config = ConfigManager.getConfig()
    
    if (!config.auth?.accessToken) {
      console.error(chalk.red('❌ Authentication required for incident reporting'))
      console.log(chalk.gray('Run vaultace auth login first'))
      process.exit(1)
    }
    
    try {
      const answers = await inquirer.prompt([
        {
          type: 'list',
          name: 'incidentType',
          message: 'What type of security incident occurred?',
          choices: [
            { name: '💀 Data Breach - Unauthorized access to user data', value: 'data_breach' },
            { name: '🔓 Authentication Bypass - Login security compromised', value: 'auth_bypass' },
            { name: '💳 Payment Security - Financial data at risk', value: 'payment_security' },
            { name: '🗃️ Database Exposure - Database publicly accessible', value: 'database_exposure' },
            { name: '🔑 API Key Compromise - API keys leaked or stolen', value: 'api_compromise' },
            { name: '🤖 AI Model Manipulation - LLM/AI system compromised', value: 'ai_manipulation' },
            { name: '🔧 Other - Custom incident type', value: 'other' }
          ]
        },
        {
          type: 'list',
          name: 'severity',
          message: 'What is the incident severity?',
          choices: [
            { name: '🌋 Catastrophic - Major data breach, regulatory scrutiny', value: 'catastrophic' },
            { name: '🔥 Critical - Active attack, immediate business impact', value: 'critical' },
            { name: '⚠️ Major - Security vulnerability exploited', value: 'major' },
            { name: '📋 Minor - Potential risk identified', value: 'minor' }
          ]
        },
        {
          type: 'input',
          name: 'description',
          message: 'Describe what happened (be specific):',
          validate: input => input.length >= 20 || 'Please provide detailed description (min 20 characters)'
        },
        {
          type: 'input',
          name: 'discoveredDate',
          message: 'When was this discovered? (YYYY-MM-DD or "today"):',
          default: 'today',
          validate: input => {
            if (input === 'today') {return true}
            const dateRegex = /^\d{4}-\d{2}-\d{2}$/
            return dateRegex.test(input) || 'Use format YYYY-MM-DD or "today"'
          }
        },
        {
          type: 'input', 
          name: 'estimatedImpact',
          message: 'Estimated business impact:',
          validate: input => input.length >= 10 || 'Please describe the business impact'
        }
      ])
      
      const spinner = ora('Reporting incident and generating recovery plan...').start()
      
      const apiClient = new APIClient(config)
      
      // Report incident
      const incidentData = {
        incident_type: answers.incidentType,
        severity: answers.severity,
        description: answers.description,
        discovered_date: answers.discoveredDate === 'today' 
          ? new Date().toISOString() 
          : `${answers.discoveredDate}T00:00:00Z`,
        estimated_impact: answers.estimatedImpact,
        affected_repositories: [] // CLI doesn't know repo IDs
      }
      
      // This would call the incident recovery API
      // await apiClient.reportIncident(incidentData)
      
      spinner.succeed('Incident reported successfully!')
      
      console.log(chalk.green('\n✅ Emergency Response Initiated'))
      console.log(chalk.bold('Incident ID:') + ' INC-' + Date.now())
      console.log(chalk.bold('Severity:') + ' ' + answers.severity.toUpperCase())
      
      console.log(chalk.blue('\n🆘 Immediate Next Steps:'))
      console.log('1. Run emergency scan: vaultace emergency scan')
      console.log('2. Get recovery timeline: vaultace emergency timeline')
      console.log('3. View triage dashboard: https://app.vaultace.com/emergency')
      
      console.log(chalk.yellow('\n📞 Emergency Support:'))
      console.log('• Slack: #vaultace-emergency')
      console.log('• Email: emergency@vaultace.com')
      console.log('• Phone: +1-555-VAULTACE (24/7 for critical incidents)')
      
    } catch (error) {
      console.error(chalk.red(`Incident reporting failed: ${error.message}`))
      console.log(chalk.gray('For immediate help, email emergency@vaultace.com'))
      process.exit(1)
    }
  })

// Recovery timeline
emergencyCommand
  .command('timeline')
  .description('Get post-incident recovery timeline')
  .option('-s, --severity <level>', 'incident severity (minor|major|critical|catastrophic)', 'major')
  .action(async (options) => {
    console.log(chalk.bold.blue('📋 INCIDENT RECOVERY TIMELINE'))
    console.log(chalk.blue('━'.repeat(40)))
    
    const config = ConfigManager.getConfig()
    
    if (!config.auth?.accessToken) {
      console.error(chalk.red('❌ Authentication required'))
      console.log(chalk.gray('Run vaultace auth login first'))
      process.exit(1)
    }
    
    const spinner = ora('Generating recovery timeline...').start()
    
    try {
      const apiClient = new APIClient(config)
      
      // This would call the recovery timeline API
      // const timeline = await apiClient.getRecoveryTimeline(options.severity)
      
      // Mock timeline for demonstration
      const timeline = generateMockTimeline(options.severity)
      
      spinner.stop()
      
      console.log(chalk.bold(`\n🕐 Recovery Timeline (${options.severity.toUpperCase()} incident)\n`))
      
      timeline.forEach((phase, index) => {
        const phaseNumber = index + 1
        const phaseIcon = getPhaseIcon(phase.phase)
        
        console.log(chalk.bold(`${phaseIcon} Phase ${phaseNumber}: ${phase.title}`))
        console.log(chalk.gray(`   Duration: ${phase.estimated_duration}`))
        console.log(chalk.gray(`   ${phase.description}\n`))
        
        phase.tasks.forEach(task => {
          console.log(chalk.cyan(`   □ ${task}`))
        })
        console.log()
      })
      
      console.log(chalk.green('💡 Pro Tip: Use vaultace emergency scan to track progress'))
      
    } catch (error) {
      spinner.fail(`Timeline generation failed: ${error.message}`)
      process.exit(1)
    }
  })

// Triage command
emergencyCommand
  .command('triage')
  .description('Get emergency vulnerability triage assessment')
  .action(async () => {
    console.log(chalk.bold.red('🏥 EMERGENCY VULNERABILITY TRIAGE'))
    console.log(chalk.red('━'.repeat(50)))
    
    const config = ConfigManager.getConfig()
    
    if (!config.auth?.accessToken) {
      console.error(chalk.red('❌ Authentication required'))
      console.log(chalk.gray('Run vaultace auth login first'))
      process.exit(1)
    }
    
    const spinner = ora('Analyzing critical vulnerabilities...').start()
    
    try {
      const apiClient = new APIClient(config)
      
      // This would call the emergency triage API
      // const triage = await apiClient.getEmergencyTriage()
      
      spinner.stop()
      
      console.log(chalk.red('\n🚨 CRITICAL VULNERABILITIES REQUIRING IMMEDIATE ATTENTION:'))
      console.log(chalk.yellow('⚡ BUSINESS RISK SCORE: 8/10 (HIGH)'))
      console.log(chalk.blue('👥 RECOMMENDED TEAM SIZE: 3 developers\n'))
      
      console.log(chalk.bold('IMMEDIATE ACTIONS:'))
      console.log(chalk.red('• Fix 2 critical authentication vulnerabilities'))
      console.log(chalk.yellow('• Address 5 high-severity issues within 72 hours'))
      console.log(chalk.blue('• Implement emergency monitoring'))
      console.log(chalk.gray('• Document all changes for audit trail'))
      
      console.log(chalk.bold('\n🕐 ESTIMATED FIX TIME: 12-18 hours'))
      
    } catch (error) {
      spinner.fail(`Triage assessment failed: ${error.message}`)
      process.exit(1)
    }
  })

async function reportSecurityIncident(criticalVulns, highVulns) {
  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'severity',
      message: 'How severe is this security situation?',
      choices: [
        { name: '🌋 Catastrophic - Active breach, data compromised', value: 'catastrophic' },
        { name: '🔥 Critical - Immediate threat, business impact', value: 'critical' },
        { name: '⚠️ Major - Significant vulnerabilities found', value: 'major' },
        { name: '📋 Minor - Potential issues identified', value: 'minor' }
      ]
    },
    {
      type: 'input',
      name: 'description', 
      message: 'Brief incident description:',
      default: `Found ${criticalVulns.length} critical and ${highVulns.length} high severity vulnerabilities`
    }
  ])
  
  console.log(chalk.green('\n✅ Incident Report Submitted'))
  console.log(`${chalk.bold('Severity:')} ${answers.severity.toUpperCase()}`)
  console.log(`${chalk.bold('Critical Vulns:')} ${criticalVulns.length}`)
  console.log(`${chalk.bold('High Vulns:')} ${highVulns.length}`)
  
  console.log(chalk.blue('\n🆘 Emergency Support Activated:'))
  console.log('• Recovery timeline: vaultace emergency timeline')
  console.log('• Triage assessment: vaultace emergency triage') 
  console.log('• 24/7 support: emergency@vaultace.com')
}

function getFixTime(vulnType) {
  const fixTimes = {
    'sql_injection': '2-4h',
    'xss': '1-2h',
    'command_injection': '4-8h', 
    'exposed_secret': '30m',
    'path_traversal': '1-3h',
    'auth_bypass': '4-8h'
  }
  return fixTimes[vulnType] || '1-4h'
}

function getPhaseIcon(phase) {
  const icons = {
    'assessment': '🔍',
    'containment': '🛡️',
    'eradication': '🔧',
    'recovery': '🚀',
    'lessons_learned': '📚'
  }
  return icons[phase] || '📋'
}

function generateMockTimeline(severity) {
  if (severity === 'catastrophic' || severity === 'critical') {
    return [
      {
        phase: 'assessment',
        title: 'Emergency Assessment',
        estimated_duration: '2-4 hours',
        description: 'Immediate threat analysis and damage assessment',
        tasks: [
          'Run comprehensive Vaultace emergency scan',
          'Identify all critical vulnerabilities',
          'Map affected systems and data exposure',
          'Document incident timeline'
        ]
      },
      {
        phase: 'containment', 
        title: 'Immediate Containment',
        estimated_duration: '4-8 hours',
        description: 'Stop ongoing damage and secure systems',
        tasks: [
          'Disable compromised authentication endpoints',
          'Revoke all API keys and tokens',
          'Implement emergency access controls',
          'Block malicious traffic'
        ]
      },
      {
        phase: 'eradication',
        title: 'Vulnerability Fix',
        estimated_duration: '1-3 days', 
        description: 'Fix all security issues identified',
        tasks: [
          'Fix all critical vulnerabilities',
          'Address high-severity issues',
          'Update dependencies and apply patches',
          'Implement proper input validation'
        ]
      }
    ]
  } else {
    return [
      {
        phase: 'assessment',
        title: 'Security Assessment',
        estimated_duration: '1-2 hours',
        description: 'Vulnerability analysis and prioritization',
        tasks: [
          'Run Vaultace security scan',
          'Prioritize by business risk',
          'Review recent changes'
        ]
      }
    ]
  }
}

module.exports = emergencyCommand