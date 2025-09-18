/**
 * Workflow Command - Vaultace SecureFlow orchestration
 * Security-focused workflow management and execution
 */

const { Command } = require('commander')
const chalk = require('chalk')
const ora = require('ora')
const inquirer = require('inquirer')
const { table } = require('table')
const logger = require('../utils/logger')

// Workflow Engine Components
const SecureFlowEngine = require('../workflows/engine/core')
const SecurityEventSystem = require('../workflows/engine/events')
const EncryptedStateManager = require('../workflows/engine/state')
const { SecurityStepTemplates } = require('../workflows/engine/steps')

// Workflow Templates
const VulnerabilityWorkflowTemplates = require('../workflows/templates/vulnerability')
const IncidentResponseWorkflowTemplates = require('../workflows/templates/incident')

const workflowCommand = new Command('workflow')
  .description('🔄 Security workflow orchestration and automation')

// Global workflow engine instance
let workflowEngine = null
let eventSystem = null
let stateManager = null

async function initializeEngine() {
  if (!workflowEngine) {
    stateManager = new EncryptedStateManager()
    eventSystem = new SecurityEventSystem()
    workflowEngine = new SecureFlowEngine({
      stateManager,
      eventSystem
    })

    // Set up event listeners
    eventSystem.on('trigger:activated', async ({ trigger, event, workflows }) => {
      for (const workflowId of workflows) {
        try {
          await workflowEngine.executeWorkflow(workflowId, event.data)
        } catch (error) {
          logger.error('Workflow execution failed', {
            workflow_id: workflowId,
            trigger_id: trigger.id,
            error: error.message
          })
        }
      }
    })
  }
  return workflowEngine
}

// List workflows
workflowCommand
  .command('list')
  .description('List available workflows')
  .option('--status <status>', 'filter by status (running|completed|failed)')
  .option('--category <category>', 'filter by category')
  .action(async (options) => {
    const spinner = ora('Loading workflows...').start()

    try {
      const engine = await initializeEngine()
      const workflows = engine.listWorkflows()

      spinner.succeed('Workflows loaded')

      if (workflows.length === 0) {
        console.log(chalk.gray('No workflows found'))
        console.log(chalk.blue('Create a workflow with: vaultace workflow create'))
        return
      }

      const workflowData = [
        ['ID', 'Name', 'Category', 'Status', 'Last Run']
      ]

      for (const workflowId of workflows) {
        const workflow = engine.getWorkflow(workflowId)
        const executions = engine.listExecutions(workflowId)
        const lastExecution = executions[executions.length - 1]

        if (options.status && lastExecution?.status !== options.status) {continue}
        if (options.category && workflow.definition?.category !== options.category) {continue}

        workflowData.push([
          workflowId.substring(0, 12) + '...',
          workflow.definition?.name || 'Unknown',
          workflow.definition?.category || 'general',
          lastExecution?.status || 'never_run',
          lastExecution ? new Date(lastExecution.startTime).toLocaleString() : 'Never'
        ])
      }

      console.log(chalk.bold.blue('\n🔄 Security Workflows\n'))
      console.log(table(workflowData))

    } catch (error) {
      spinner.fail('Failed to list workflows')
      logger.error('Workflow list error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Create workflow
workflowCommand
  .command('create')
  .description('Create a new security workflow')
  .option('--template <template>', 'use a predefined template')
  .option('--category <category>', 'workflow category')
  .option('--interactive', 'interactive workflow builder')
  .action(async (options) => {
    try {
      const engine = await initializeEngine()

      if (options.template) {
        await createFromTemplate(engine, options.template)
      } else if (options.interactive) {
        await createInteractive(engine, options)
      } else {
        await showTemplateOptions()
      }

    } catch (error) {
      logger.error('Workflow creation error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Run workflow
workflowCommand
  .command('run <workflow-id>')
  .description('Execute a workflow')
  .option('--trigger-data <data>', 'trigger data as JSON string')
  .option('--dry-run', 'simulate execution without making changes')
  .action(async (workflowId, options) => {
    const spinner = ora('Starting workflow execution...').start()

    try {
      const engine = await initializeEngine()

      let triggerData = {}
      if (options.triggerData) {
        triggerData = JSON.parse(options.triggerData)
      }

      const executionId = await engine.executeWorkflow(workflowId, triggerData, {
        dryRun: options.dryRun
      })

      spinner.succeed('Workflow execution started')

      console.log(chalk.green('\n✅ Workflow execution initiated'))
      console.log(`Execution ID: ${executionId}`)
      console.log(`Monitor with: vaultace workflow monitor ${executionId}`)

      if (options.dryRun) {
        console.log(chalk.yellow('Note: This was a dry run - no actual changes were made'))
      }

    } catch (error) {
      spinner.fail('Failed to start workflow execution')
      logger.error('Workflow execution error', {
        workflow_id: workflowId,
        error: error.message
      })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Monitor workflow execution
workflowCommand
  .command('monitor <execution-id>')
  .description('Monitor workflow execution')
  .option('--follow', 'follow execution in real-time')
  .option('--detailed', 'show detailed step information')
  .action(async (executionId, options) => {
    try {
      const engine = await initializeEngine()

      if (options.follow) {
        await followExecution(engine, executionId, options.detailed)
      } else {
        await showExecutionStatus(engine, executionId, options.detailed)
      }

    } catch (error) {
      logger.error('Workflow monitoring error', {
        execution_id: executionId,
        error: error.message
      })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Show workflow templates
workflowCommand
  .command('templates')
  .description('List available workflow templates')
  .option('--category <category>', 'filter by category')
  .action(async (options) => {
    console.log(chalk.bold.cyan('\n🔄 Vaultace SecureFlow Templates\n'))

    const templates = {
      'Vulnerability Management': VulnerabilityWorkflowTemplates.getAllTemplates(),
      'Incident Response': IncidentResponseWorkflowTemplates.getAllTemplates()
    }

    for (const [category, categoryTemplates] of Object.entries(templates)) {
      if (options.category && category.toLowerCase() !== options.category.toLowerCase()) {
        continue
      }

      console.log(chalk.bold.yellow(`\n${category}:`))

      for (const [templateId, template] of Object.entries(categoryTemplates)) {
        console.log(`  ${chalk.green(templateId.padEnd(25))} - ${template.description}`)
        console.log(`  ${chalk.gray('Steps:')} ${template.steps.length} | ${chalk.gray('Priority:')} ${template.priority || 'normal'}`)
        console.log('')
      }
    }

    console.log(chalk.blue('Create from template: vaultace workflow create --template <template-name>'))
  })

// Stop workflow execution
workflowCommand
  .command('stop <execution-id>')
  .description('Stop a running workflow execution')
  .option('--force', 'force stop without graceful shutdown')
  .action(async (executionId, options) => {
    const spinner = ora('Stopping workflow execution...').start()

    try {
      const engine = await initializeEngine()
      await engine.stopExecution(executionId)

      spinner.succeed('Workflow execution stopped')

      console.log(chalk.green(`\n✅ Workflow execution ${executionId} stopped`))

    } catch (error) {
      spinner.fail('Failed to stop workflow execution')
      logger.error('Workflow stop error', {
        execution_id: executionId,
        error: error.message
      })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Replay workflow execution from specific step
workflowCommand
  .command('replay <execution-id>')
  .description('Replay workflow execution from a specific step')
  .option('--from-step <step>', 'step index to replay from', '0')
  .action(async (executionId, options) => {
    const spinner = ora('Starting workflow replay...').start()

    try {
      const engine = await initializeEngine()
      const fromStep = parseInt(options.fromStep)

      await engine.replayExecution(executionId, fromStep)

      spinner.succeed('Workflow replay completed')

      console.log(chalk.green(`\n✅ Workflow ${executionId} replayed from step ${fromStep}`))

    } catch (error) {
      spinner.fail('Failed to replay workflow')
      logger.error('Workflow replay error', {
        execution_id: executionId,
        error: error.message
      })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Manage workflow triggers
workflowCommand
  .command('triggers')
  .description('Manage workflow triggers')
  .option('--list', 'list all triggers')
  .option('--create', 'create new trigger')
  .option('--enable <trigger-id>', 'enable trigger')
  .option('--disable <trigger-id>', 'disable trigger')
  .action(async (options) => {
    try {
      const engine = await initializeEngine()
      const events = engine.config.eventSystem

      if (options.list) {
        await listTriggers(events)
      } else if (options.create) {
        await createTrigger(events)
      } else if (options.enable) {
        events.enableTrigger(options.enable)
        console.log(chalk.green(`Trigger ${options.enable} enabled`))
      } else if (options.disable) {
        events.disableTrigger(options.disable)
        console.log(chalk.yellow(`Trigger ${options.disable} disabled`))
      } else {
        console.log(chalk.yellow('Please specify an action: --list, --create, --enable, or --disable'))
      }

    } catch (error) {
      logger.error('Trigger management error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Helper functions

async function createFromTemplate(engine, templateName) {
  const spinner = ora('Creating workflow from template...').start()

  try {
    const allTemplates = {
      ...VulnerabilityWorkflowTemplates.getAllTemplates(),
      ...IncidentResponseWorkflowTemplates.getAllTemplates()
    }

    const template = allTemplates[templateName]
    if (!template) {
      spinner.fail('Template not found')
      console.log(chalk.red(`Template '${templateName}' not found`))
      console.log(chalk.blue('Available templates: vaultace workflow templates'))
      return
    }

    const workflowId = await engine.registerWorkflow(template)

    spinner.succeed('Workflow created from template')

    console.log(chalk.green(`\n✅ Workflow created: ${workflowId}`))
    console.log(`Template: ${templateName}`)
    console.log(`Name: ${template.name}`)
    console.log(`Steps: ${template.steps.length}`)
    console.log(`Run with: vaultace workflow run ${workflowId}`)

  } catch (error) {
    spinner.fail('Failed to create workflow from template')
    throw error
  }
}

async function showTemplateOptions() {
  console.log(chalk.bold.cyan('\n🔄 Workflow Creation Options\n'))

  console.log(chalk.yellow('Option 1: Use a predefined template'))
  console.log('  vaultace workflow create --template <template-name>')
  console.log('  vaultace workflow templates  # See available templates\n')

  console.log(chalk.yellow('Option 2: Interactive workflow builder'))
  console.log('  vaultace workflow create --interactive\n')

  console.log(chalk.yellow('Popular templates:'))
  console.log('  • cve_response - Automated CVE vulnerability patching')
  console.log('  • zero_day_response - Emergency zero-day response')
  console.log('  • data_breach_response - GDPR/HIPAA compliant breach response')
  console.log('  • ransomware_response - Comprehensive ransomware recovery')
}

async function showExecutionStatus(engine, executionId, detailed) {
  const execution = engine.getExecution(executionId)

  if (!execution) {
    console.log(chalk.red(`Execution ${executionId} not found`))
    return
  }

  console.log(chalk.bold.blue('\n📊 Workflow Execution Status\n'))
  console.log(`Execution ID: ${executionId}`)
  console.log(`Status: ${getStatusColor(execution.status)}`)
  console.log(`Started: ${new Date(execution.startTime).toLocaleString()}`)

  if (execution.endTime) {
    console.log(`Completed: ${new Date(execution.endTime).toLocaleString()}`)
    console.log(`Duration: ${execution.endTime - execution.startTime}ms`)
  }

  console.log(`Current Step: ${execution.currentStep + 1}/${execution.steps.length || 'Unknown'}`)

  if (detailed && execution.steps) {
    console.log(chalk.bold.yellow('\nStep Details:'))

    execution.steps.forEach((step, index) => {
      const status = getStatusColor(step.status)
      const duration = step.endTime ? `${step.endTime - step.startTime}ms` : 'Running...'
      console.log(`  ${index + 1}. ${step.name} - ${status} (${duration})`)
    })
  }

  if (execution.error) {
    console.log(chalk.red(`\nError: ${execution.error}`))
  }
}

async function followExecution(engine, executionId, detailed) {
  console.log(chalk.blue(`Following execution ${executionId}...`))
  console.log(chalk.gray('Press Ctrl+C to stop following\n'))

  const execution = engine.getExecution(executionId)
  if (!execution) {
    console.log(chalk.red(`Execution ${executionId} not found`))
    return
  }

  let lastStepCount = 0

  const followInterval = setInterval(async () => {
    const currentExecution = engine.getExecution(executionId)

    if (currentExecution.steps.length > lastStepCount) {
      const newSteps = currentExecution.steps.slice(lastStepCount)

      newSteps.forEach((step, index) => {
        const stepNum = lastStepCount + index + 1
        const status = getStatusColor(step.status)
        console.log(`Step ${stepNum}: ${step.name} - ${status}`)
      })

      lastStepCount = currentExecution.steps.length
    }

    if (currentExecution.status === 'completed' || currentExecution.status === 'failed') {
      clearInterval(followInterval)
      console.log(chalk.green(`\nExecution ${currentExecution.status}`))
    }
  }, 2000)
}

async function listTriggers(eventSystem) {
  const triggers = eventSystem.listTriggers()

  if (triggers.length === 0) {
    console.log(chalk.gray('No triggers configured'))
    return
  }

  console.log(chalk.bold.blue('\n🎯 Workflow Triggers\n'))

  const triggerData = [
    ['ID', 'Type', 'Status', 'Workflows', 'Created']
  ]

  triggers.forEach(trigger => {
    triggerData.push([
      trigger.id.substring(0, 12) + '...',
      trigger.type,
      trigger.enabled ? '✅ Enabled' : '❌ Disabled',
      trigger.workflows.size.toString(),
      new Date(trigger.createdAt).toLocaleDateString()
    ])
  })

  console.log(table(triggerData))
}

async function createTrigger(eventSystem) {
  console.log(chalk.yellow('Interactive trigger creation not yet implemented'))
  console.log(chalk.blue('Use templates for pre-configured triggers'))
}

function getStatusColor(status) {
  const colors = {
    running: chalk.blue('🔄 Running'),
    completed: chalk.green('✅ Completed'),
    failed: chalk.red('❌ Failed'),
    stopped: chalk.yellow('⏹️  Stopped'),
    pending: chalk.gray('⏳ Pending')
  }
  return colors[status] || chalk.gray(`❓ ${status}`)
}

module.exports = workflowCommand