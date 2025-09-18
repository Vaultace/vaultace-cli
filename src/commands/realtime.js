/**
 * Real-time Command - WebSocket monitoring and live updates
 */

const { Command } = require('commander')
const chalk = require('chalk')
const ora = require('ora')
const WebSocket = require('ws')
const { getAPIClient } = require('../services/api-client')

const realtimeCommand = new Command('realtime')
  .alias('live')
  .description('⚡ Real-time monitoring and live security updates')

// Live vulnerability monitoring
realtimeCommand
  .command('monitor')
  .description('Monitor vulnerabilities in real-time')
  .option('--repository <repo>', 'specific repository to monitor')
  .option('--severity <level>', 'minimum severity to monitor', 'medium')
  .action(async (options) => {
    const apiClient = getAPIClient()

    if (!apiClient.isAuthenticated()) {
      console.log(chalk.yellow('Please login first: vaultace auth login'))
      return
    }

    console.log(chalk.bold.cyan('⚡ Vaultace Real-time Vulnerability Monitor'))
    console.log(chalk.gray('Press Ctrl+C to stop monitoring\n'))

    if (options.repository) {
      console.log(`Repository: ${options.repository}`)
    }
    console.log(`Minimum Severity: ${options.severity.toUpperCase()}`)
    console.log(chalk.gray('Connecting to real-time feed...\n'))

    // WebSocket reconnection logic
    let reconnectAttempts = 0
    const maxReconnectAttempts = 5
    const reconnectDelay = 1000 // Start with 1 second
    let isUserDisconnect = false

    function connectWebSocket() {
      try {
        const wsUrl = apiClient.baseURL.replace('https:', 'wss:').replace('http:', 'ws:') + '/ws/vulnerabilities'
        const ws = new WebSocket(wsUrl, {
          headers: {
            'Authorization': `Bearer ${apiClient.getAuthToken ? apiClient.getAuthToken() : apiClient.config.get('auth.token')}`
          }
        })

        ws.on('open', () => {
          reconnectAttempts = 0 // Reset counter on successful connection
          console.log(chalk.green('🔗 Connected to real-time feed'))

          // Subscribe to vulnerability events
          ws.send(JSON.stringify({
            type: 'subscribe',
            channel: 'vulnerabilities',
            filters: {
              repository: options.repository,
              min_severity: options.severity
            }
          }))
        })

        ws.on('message', (data) => {
          try {
            const event = JSON.parse(data.toString())
            handleVulnerabilityEvent(event)
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error)
          }
        })

        ws.on('error', (error) => {
          console.error(chalk.red('WebSocket error:'), error.message)
        })

        ws.on('close', (code, reason) => {
          if (isUserDisconnect) {
            console.log(chalk.yellow('🔌 Connection closed by user'))
            return
          }

          console.log(chalk.yellow('🔌 Connection closed'))

          // Attempt to reconnect if not intentionally closed
          if (reconnectAttempts < maxReconnectAttempts) {
            reconnectAttempts++
            const delay = reconnectDelay * Math.pow(2, reconnectAttempts - 1) // Exponential backoff
            console.log(chalk.gray(`⏳ Attempting to reconnect (${reconnectAttempts}/${maxReconnectAttempts}) in ${delay}ms...`))

            setTimeout(() => {
              if (!isUserDisconnect) {
                connectWebSocket()
              }
            }, delay)
          } else {
            console.error(chalk.red('❌ Maximum reconnection attempts reached. Please restart the monitor.'))
            process.exit(1)
          }
        })

        // Keep process alive
        process.on('SIGINT', () => {
          console.log(chalk.yellow('\n📡 Stopping real-time monitor...'))
          isUserDisconnect = true
          ws.close()
          process.exit(0)
        })

        return ws
      } catch (error) {
        console.error(chalk.red('Failed to connect to real-time feed:'), error.message)
        if (reconnectAttempts < maxReconnectAttempts) {
          reconnectAttempts++
          setTimeout(() => connectWebSocket(), reconnectDelay * reconnectAttempts)
        }
      }
    }

    // Start initial connection
    connectWebSocket()
  })

// Live scan progress
realtimeCommand
  .command('scan-progress <scan-id>')
  .description('Monitor scan progress in real-time')
  .action(async (scanId) => {
    const apiClient = getAPIClient()

    if (!apiClient.isAuthenticated()) {
      console.log(chalk.yellow('Please login first: vaultace auth login'))
      return
    }

    console.log(chalk.bold.blue('🔍 Real-time Scan Progress Monitor'))
    console.log(`Scan ID: ${scanId}\n`)

    try {
      const wsUrl = apiClient.baseURL.replace('https:', 'wss:').replace('http:', 'ws:') + '/ws/scans'
      const ws = new WebSocket(wsUrl, {
        headers: {
          'Authorization': `Bearer ${apiClient.config.get('auth.token')}`
        }
      })

      ws.on('open', () => {
        console.log(chalk.green('🔗 Connected to scan monitor'))

        ws.send(JSON.stringify({
          type: 'subscribe',
          channel: 'scan_progress',
          scan_id: scanId
        }))
      })

      ws.on('message', (data) => {
        try {
          const event = JSON.parse(data.toString())
          handleScanProgressEvent(event)
        } catch (error) {
          console.error('Failed to parse scan progress:', error)
        }
      })

      ws.on('close', () => {
        console.log(chalk.yellow('🔌 Scan monitoring ended'))
      })

      process.on('SIGINT', () => {
        ws.close()
        process.exit(0)
      })

    } catch (error) {
      console.error(chalk.red('Failed to monitor scan:'), error.message)
    }
  })

// Live workflow execution
realtimeCommand
  .command('workflow-execution <execution-id>')
  .description('Monitor workflow execution in real-time')
  .action(async (executionId) => {
    const apiClient = getAPIClient()

    if (!apiClient.isAuthenticated()) {
      console.log(chalk.yellow('Please login first: vaultace auth login'))
      return
    }

    console.log(chalk.bold.magenta('🔄 Real-time Workflow Monitor'))
    console.log(`Execution ID: ${executionId}\n`)

    try {
      const wsUrl = apiClient.baseURL.replace('https:', 'wss:').replace('http:', 'ws:') + '/ws/workflows'
      const ws = new WebSocket(wsUrl, {
        headers: {
          'Authorization': `Bearer ${apiClient.config.get('auth.token')}`
        }
      })

      ws.on('open', () => {
        console.log(chalk.green('🔗 Connected to workflow monitor'))

        ws.send(JSON.stringify({
          type: 'subscribe',
          channel: 'workflow_execution',
          execution_id: executionId
        }))
      })

      ws.on('message', (data) => {
        try {
          const event = JSON.parse(data.toString())
          handleWorkflowEvent(event)
        } catch (error) {
          console.error('Failed to parse workflow event:', error)
        }
      })

      ws.on('close', () => {
        console.log(chalk.yellow('🔌 Workflow monitoring ended'))
      })

      process.on('SIGINT', () => {
        ws.close()
        process.exit(0)
      })

    } catch (error) {
      console.error(chalk.red('Failed to monitor workflow:'), error.message)
    }
  })

// Live security alerts
realtimeCommand
  .command('alerts')
  .description('Stream live security alerts')
  .option('--critical-only', 'only show critical alerts')
  .action(async (options) => {
    const apiClient = getAPIClient()

    if (!apiClient.isAuthenticated()) {
      console.log(chalk.yellow('Please login first: vaultace auth login'))
      return
    }

    console.log(chalk.bold.red('🚨 Live Security Alerts Stream'))
    console.log(chalk.gray('Press Ctrl+C to stop monitoring\n'))

    try {
      const wsUrl = apiClient.baseURL.replace('https:', 'wss:').replace('http:', 'ws:') + '/ws/alerts'
      const ws = new WebSocket(wsUrl, {
        headers: {
          'Authorization': `Bearer ${apiClient.config.get('auth.token')}`
        }
      })

      ws.on('open', () => {
        console.log(chalk.green('🔗 Connected to alerts stream'))

        ws.send(JSON.stringify({
          type: 'subscribe',
          channel: 'security_alerts',
          filters: {
            critical_only: options.criticalOnly
          }
        }))
      })

      ws.on('message', (data) => {
        try {
          const alert = JSON.parse(data.toString())
          handleSecurityAlert(alert)
        } catch (error) {
          console.error('Failed to parse alert:', error)
        }
      })

      ws.on('close', () => {
        console.log(chalk.yellow('🔌 Alert stream ended'))
      })

      process.on('SIGINT', () => {
        ws.close()
        process.exit(0)
      })

    } catch (error) {
      console.error(chalk.red('Failed to connect to alerts:'), error.message)
    }
  })

// Event handlers
function handleVulnerabilityEvent(event) {
  const timestamp = new Date().toLocaleTimeString()

  switch (event.type) {
  case 'vulnerability_detected':
    console.log(chalk.red(`[${timestamp}] 🔍 NEW VULNERABILITY DETECTED`))
    console.log(`  Repository: ${event.data.repository}`)
    console.log(`  File: ${event.data.file_path}`)
    console.log(`  Severity: ${getSeverityColor(event.data.severity)}`)
    console.log(`  Type: ${event.data.vulnerability_type}`)
    if (event.data.ai_confidence) {
      console.log(`  AI Confidence: ${event.data.ai_confidence}%`)
    }
    console.log('')
    break

  case 'vulnerability_fixed':
    console.log(chalk.green(`[${timestamp}] ✅ VULNERABILITY FIXED`))
    console.log(`  Repository: ${event.data.repository}`)
    console.log(`  Fix Method: ${event.data.fix_method}`)
    console.log(`  Time to Fix: ${event.data.time_to_fix}`)
    console.log('')
    break

  case 'vulnerability_escalated':
    console.log(chalk.yellow(`[${timestamp}] ⚠️  VULNERABILITY ESCALATED`))
    console.log(`  Repository: ${event.data.repository}`)
    console.log(`  Reason: ${event.data.escalation_reason}`)
    console.log('')
    break
  }
}

function handleScanProgressEvent(event) {
  const timestamp = new Date().toLocaleTimeString()

  switch (event.type) {
  case 'scan_started':
    console.log(chalk.blue(`[${timestamp}] 🚀 Scan started`))
    console.log(`  Files to scan: ${event.data.total_files}`)
    break

  case 'scan_progress':
    const progress = event.data.progress
    const progressBar = '█'.repeat(Math.floor(progress / 5)) + '░'.repeat(20 - Math.floor(progress / 5))
    console.log(`[${timestamp}] Progress: [${progressBar}] ${progress}%`)
    if (event.data.current_file) {
      console.log(`  Scanning: ${event.data.current_file}`)
    }
    break

  case 'scan_completed':
    console.log(chalk.green(`[${timestamp}] ✅ Scan completed`))
    console.log(`  Vulnerabilities found: ${event.data.vulnerabilities_count}`)
    console.log(`  Duration: ${event.data.duration}ms`)
    break

  case 'scan_failed':
    console.log(chalk.red(`[${timestamp}] ❌ Scan failed`))
    console.log(`  Error: ${event.data.error}`)
    break
  }
}

function handleWorkflowEvent(event) {
  const timestamp = new Date().toLocaleTimeString()

  switch (event.type) {
  case 'workflow_started':
    console.log(chalk.cyan(`[${timestamp}] 🔄 Workflow started`))
    console.log(`  Total steps: ${event.data.total_steps}`)
    break

  case 'step_started':
    console.log(`[${timestamp}] ▶️  Step ${event.data.step_index + 1}: ${event.data.step_name}`)
    break

  case 'step_completed':
    console.log(`[${timestamp}] ✅ Step ${event.data.step_index + 1} completed`)
    if (event.data.duration) {
      console.log(`  Duration: ${event.data.duration}ms`)
    }
    break

  case 'step_failed':
    console.log(chalk.red(`[${timestamp}] ❌ Step ${event.data.step_index + 1} failed`))
    console.log(`  Error: ${event.data.error}`)
    break

  case 'workflow_completed':
    console.log(chalk.green(`[${timestamp}] 🎉 Workflow completed successfully`))
    console.log(`  Total duration: ${event.data.total_duration}ms`)
    break

  case 'workflow_failed':
    console.log(chalk.red(`[${timestamp}] 💥 Workflow failed`))
    console.log(`  Error: ${event.data.error}`)
    break
  }
}

function handleSecurityAlert(alert) {
  const timestamp = new Date().toLocaleTimeString()

  console.log(chalk.red(`[${timestamp}] 🚨 SECURITY ALERT`))
  console.log(`  Severity: ${getSeverityColor(alert.severity)}`)
  console.log(`  Title: ${alert.title}`)
  console.log(`  Description: ${alert.description}`)

  if (alert.repository) {
    console.log(`  Repository: ${alert.repository}`)
  }

  if (alert.action_required) {
    console.log(chalk.yellow(`  ⚠️  Action Required: ${alert.action_required}`))
  }

  console.log('')
}

function getSeverityColor(severity) {
  const colors = {
    critical: chalk.red('CRITICAL'),
    high: chalk.red('HIGH'),
    medium: chalk.yellow('MEDIUM'),
    low: chalk.blue('LOW')
  }
  return colors[severity] || severity.toUpperCase()
}

module.exports = realtimeCommand