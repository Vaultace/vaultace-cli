/**
 * LLM Guardrails Command
 * CLI interface for LLM security guardrails
 */

const { Command } = require('commander')
const LLMGuardrails = require('../services/llm-guardrails')
const logger = require('../utils/logger')
const fs = require('fs-extra')

function createLLMGuardrailsCommand() {
  const cmd = new Command('guardrails')
    .description('Run LLM security guardrails on text, prompts, or responses')
    .option('-t, --text <text>', 'Text to check')
    .option('-f, --file <file>', 'File containing text to check')
    .option('-type, --type <type>', 'Type of check: prompt, response, sql', 'prompt')
    .option('-s, --severity <level>', 'Minimum severity level', 'medium')
    .option('--json', 'Output results in JSON format')
    .option('--stats', 'Show guardrail statistics')
    .option('--interactive', 'Interactive mode for testing prompts')
    .action(async (options) => {
      try {
        const guardrails = new LLMGuardrails({
          verbose: options.verbose,
          severityThreshold: options.severity
        })

        if (options.stats) {
          const stats = guardrails.getStats()
          if (options.json) {
            console.log(JSON.stringify(stats, null, 2))
          } else {
            logger.info('LLM Guardrails Statistics:')
            console.log(`Total Checks: ${stats.totalChecks}`)
            console.log(`Blocked Requests: ${stats.blockedRequests}`)
            console.log(`Flagged Responses: ${stats.flaggedResponses}`)
            console.log(`Success Rate: ${stats.successRate}`)
            console.log('\nGuardrail Triggers:')
            Object.entries(stats.guardrailTriggers).forEach(([type, count]) => {
              console.log(`  ${type}: ${count}`)
            })
          }
          return
        }

        if (options.interactive) {
          await runInteractiveMode(guardrails, options)
          return
        }

        let textToCheck = ''

        if (options.file) {
          if (!await fs.exists(options.file)) {
            logger.error(`File not found: ${options.file}`)
            process.exit(1)
          }
          textToCheck = await fs.readFile(options.file, 'utf8')
        } else if (options.text) {
          textToCheck = options.text
        } else {
          logger.error('Please provide either --text or --file option')
          process.exit(1)
        }

        // Run guardrail checks
        const result = await guardrails.checkAll(textToCheck, options.type)

        if (options.json) {
          console.log(JSON.stringify(result, null, 2))
        } else {
          displayResults(result, textToCheck, options.type)
        }

      } catch (error) {
        logger.error(`LLM Guardrails check failed: ${error.message}`)
        process.exit(1)
      }
    })

  // Subcommand for testing specific guardrails
  cmd.command('test')
    .description('Test specific guardrail')
    .argument('<guardrail>', 'Guardrail to test: injection, sensitive, offensive, inappropriate, sql, fact, quality')
    .argument('<text>', 'Text to test')
    .option('--json', 'Output in JSON format')
    .action(async (guardrail, text, options) => {
      try {
        const guardrails = new LLMGuardrails()
        let result

        switch (guardrail.toLowerCase()) {
          case 'injection':
            result = guardrails.promptInjectionShield(text)
            break
          case 'sensitive':
            result = guardrails.sensitiveContentScanner(text)
            break
          case 'offensive':
            result = guardrails.offensiveLanguageFilter(text)
            break
          case 'inappropriate':
            result = guardrails.inappropriateContentFilter(text)
            break
          case 'sql':
            result = guardrails.sqlQueryValidator(text)
            break
          case 'fact':
            result = guardrails.factCheckValidator(text)
            break
          case 'quality':
            result = guardrails.responseQualityGrader(text)
            break
          default:
            logger.error(`Unknown guardrail: ${guardrail}`)
            process.exit(1)
        }

        if (options.json) {
          console.log(JSON.stringify(result, null, 2))
        } else {
          console.log(`\n${guardrail.toUpperCase()} Guardrail Test Results:`)
          console.log('='.repeat(50))
          console.log(JSON.stringify(result, null, 2))
        }

      } catch (error) {
        logger.error(`Guardrail test failed: ${error.message}`)
        process.exit(1)
      }
    })

  return cmd
}

async function runInteractiveMode(guardrails, options) {
  const readline = require('readline')
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

  console.log('\n🛡️  LLM Guardrails Interactive Mode')
  console.log('Type your prompts to test against guardrails. Type "exit" to quit.\n')

  const question = (prompt) => new Promise((resolve) => rl.question(prompt, resolve))

  while (true) {
    try {
      const input = await question('Enter prompt to test: ')

      if (input.toLowerCase() === 'exit') {
        break
      }

      if (input.trim() === '') {
        continue
      }

      const result = await guardrails.checkAll(input, options.type)

      console.log('\n' + '='.repeat(60))
      if (result.blocked) {
        console.log('🚫 BLOCKED - Guardrail violations detected:')
        result.violations.forEach((violation, index) => {
          console.log(`  ${index + 1}. ${violation.type}: ${violation.message}`)
        })
      } else {
        console.log('✅ PASSED - No guardrail violations detected')
      }

      if (result.recommendations.length > 0) {
        console.log('\n💡 Recommendations:')
        result.recommendations.forEach((rec, index) => {
          console.log(`  ${index + 1}. ${rec}`)
        })
      }
      console.log('='.repeat(60) + '\n')

    } catch (error) {
      console.error(`Error: ${error.message}`)
    }
  }

  rl.close()
  console.log('\nExiting interactive mode.')
}

function displayResults(result, text, type) {
  console.log('\n🛡️  LLM Guardrails Analysis Results')
  console.log('='.repeat(60))
  console.log(`Type: ${type}`)
  console.log(`Text Length: ${text.length} characters`)
  console.log(`Timestamp: ${result.metadata.timestamp}`)
  console.log(`Check ID: ${result.metadata.checkId}`)

  if (result.blocked) {
    console.log('\n🚫 STATUS: BLOCKED')
    console.log('\nViolations Detected:')
    result.violations.forEach((violation, index) => {
      console.log(`\n${index + 1}. ${violation.type.toUpperCase()}`)
      console.log(`   Severity: ${violation.severity}`)
      console.log(`   Message: ${violation.message}`)
      if (violation.description) {
        console.log(`   Description: ${violation.description}`)
      }
      if (violation.recommendation) {
        console.log(`   Recommendation: ${violation.recommendation}`)
      }
    })
  } else {
    console.log('\n✅ STATUS: PASSED')
    console.log('No guardrail violations detected.')
  }

  if (result.recommendations.length > 0) {
    console.log('\n💡 Recommendations:')
    result.recommendations.forEach((rec, index) => {
      console.log(`${index + 1}. ${rec}`)
    })
  }

  console.log('\n' + '='.repeat(60))
}

module.exports = createLLMGuardrailsCommand