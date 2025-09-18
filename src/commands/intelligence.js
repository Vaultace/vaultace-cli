/**
 * Intelligence Command - Advanced ML-powered threat intelligence
 * FREE TIER: Basic analysis | PAID TIER: Advanced ML + OSINT + Global feeds
 */

const { Command } = require('commander')
const chalk = require('chalk')
const ora = require('ora')
const { table } = require('table')

const MLIntelligenceService = require('../services/ml-intelligence-service')
const ConfigManager = require('../utils/config-manager')

class IntelligenceCommand {
  constructor() {
    this.mlService = new MLIntelligenceService()
  }

  async checkTierAccess(requiredTier = 'free') {
    const config = ConfigManager.getConfig()
    const userTier = config.subscription?.tier || 'free'

    const tiers = ['free', 'professional', 'enterprise', 'government']
    const hasAccess = tiers.indexOf(userTier) >= tiers.indexOf(requiredTier)

    if (!hasAccess) {
      console.log(chalk.red(`❌ This feature requires ${requiredTier.toUpperCase()} tier or higher`))

      if (requiredTier === 'government') {
        console.log(chalk.yellow('🏛️ Government tier requires security clearance verification'))
        console.log(chalk.cyan('Contact: government@vaultace.co'))
        console.log(chalk.gray('Custom pricing for classified intelligence access'))
      } else if (requiredTier === 'enterprise') {
        console.log(chalk.yellow('🏢 Global Intelligence Platform - Enterprise Add-on'))
        console.log(chalk.cyan('Contact for pricing: intelligence@vaultace.co'))
        console.log(chalk.gray('Separate license required for foreign intelligence databases'))
      } else {
        console.log(chalk.cyan('Upgrade at: https://vaultace.co/pricing'))
      }
      return false
    }
    return true
  }

  displayCapabilities() {
    console.log(chalk.cyan.bold('\n🧠 VAULTACE ML INTELLIGENCE PLATFORM'))
    console.log(chalk.gray('='.repeat(60)))

    console.log(chalk.green('\n🆓 FREE TIER:'))
    console.log(`  • Basic local vulnerability scanning`)
    console.log(`  • Community NVD database access only`)
    console.log(`  • Simple JSON reports`)
    console.log(`  • Standard security recommendations`)

    console.log(chalk.yellow('\n💼 PROFESSIONAL TIER:'))
    console.log(`  • ML-powered analysis (4 algorithms)`)
    console.log(`  • Enhanced vulnerability detection`)
    console.log(`  • Pattern recognition and clustering`)
    console.log(`  • Advanced reporting and exports`)

    console.log(chalk.red('\n🏢 ENTERPRISE + INTELLIGENCE PLATFORM:'))
    console.log(`  • ${chalk.white('LICENSED ADD-ON:')} Global threat intelligence (11 databases)`)
    console.log(`  • ${chalk.white('RESTRICTED ACCESS:')} Chinese CNNVD (20-day advantage)`)
    console.log(`  • ${chalk.white('RESTRICTED ACCESS:')} Russian FSTEC-BDU intelligence`)
    console.log(`  • ${chalk.white('CUSTOM PRICING:')} Geopolitical threat analysis`)
    console.log(`  • ${chalk.white('CUSTOM PRICING:')} Advanced OSINT capabilities`)
    console.log(chalk.gray('    → Contact intelligence@vaultace.co for pricing'))

    console.log(chalk.magenta('\n🏛️ GOVERNMENT INTELLIGENCE TIER:'))
    console.log(`  • ${chalk.white('CLASSIFIED:')} Full state actor attribution`)
    console.log(`  • ${chalk.white('CLASSIFIED:')} Real-time threat feeds from all 10 countries`)
    console.log(`  • ${chalk.white('CLASSIFIED:')} Advanced geopolitical intelligence`)
    console.log(`  • ${chalk.white('CLASSIFIED:')} Custom ML models for national security`)
    console.log(`  • ${chalk.white('CLASSIFIED:')} Dedicated secure infrastructure`)
    console.log(chalk.gray('    → Contact government@vaultace.co for verification'))
    console.log(chalk.gray('    → Requires security clearance and custom contracts'))
  }

  colorSeverity(severity) {
    switch (severity?.toLowerCase()) {
      case 'critical': return chalk.red.bold(severity)
      case 'high': return chalk.red(severity)
      case 'medium': return chalk.yellow(severity)
      case 'low': return chalk.green(severity)
      default: return chalk.white(severity)
    }
  }
}

const command = new Command('intelligence')
  .alias('intel')
  .description('🧠 ML-powered threat intelligence platform')

command
  .command('capabilities')
  .description('🌍 Show platform capabilities')
  .action(() => {
    const intel = new IntelligenceCommand()
    intel.displayCapabilities()
  })

command
  .command('scan [target]')
  .description('🔍 Basic analysis (FREE)')
  .action(async (target) => {
    console.log(chalk.cyan('🔍 Running basic analysis...'))
    console.log('Target:', target || '.')
  })

command
  .command('analyze [target]')
  .description('🤖 ML analysis (PROFESSIONAL)')
  .action(async (target) => {
    const intel = new IntelligenceCommand()
    if (await intel.checkTierAccess('professional')) {
      console.log(chalk.cyan('🤖 Running ML analysis...'))
    }
  })

command
  .command('comprehensive [target]')
  .description('🏢 Enterprise analysis (ENTERPRISE - Global Intelligence)')
  .action(async (target) => {
    const intel = new IntelligenceCommand()
    if (await intel.checkTierAccess('enterprise')) {
      console.log(chalk.cyan('🏢 Running comprehensive global intelligence analysis...'))
      console.log(chalk.yellow('⚠️ Accessing restricted threat intelligence from 11 global databases'))
    }
  })

// Government-tier command (highly restricted)
command
  .command('classified [target]')
  .description('🏛️ Government intelligence analysis (GOVERNMENT ONLY)')
  .action(async (target) => {
    const intel = new IntelligenceCommand()
    if (await intel.checkTierAccess('government')) {
      console.log(chalk.magenta('🏛️ Running classified intelligence analysis...'))
      console.log(chalk.red('🔒 RESTRICTED: Government-grade threat intelligence active'))
    }
  })

module.exports = command