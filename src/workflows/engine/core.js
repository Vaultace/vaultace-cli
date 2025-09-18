/**
 * Vaultace SecureFlow - Core Workflow Engine
 * Security-focused workflow orchestration with end-to-end encryption
 */

const crypto = require('crypto')
const EventEmitter = require('events')
const logger = require('../../utils/logger')

class SecureFlowEngine extends EventEmitter {
  constructor(options = {}) {
    super()
    this.workflows = new Map()
    this.executions = new Map()
    this.config = {
      encryptionKey: options.encryptionKey || this.generateEncryptionKey(),
      maxRetries: options.maxRetries || 3,
      stepTimeout: options.stepTimeout || 30000,
      enableAuditLog: options.enableAuditLog !== false,
      privacyMode: options.privacyMode || false,
      ...options
    }

    logger.security('SecureFlow engine initialized', {
      privacy_mode: this.config.privacyMode,
      audit_enabled: this.config.enableAuditLog
    })
  }

  generateEncryptionKey() {
    return crypto.randomBytes(32)
  }

  encrypt(data) {
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv('aes-256-gcm', this.config.encryptionKey, iv)
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(data), 'utf8'), cipher.final()])
    const authTag = cipher.getAuthTag()
    return {
      iv: iv.toString('hex'),
      encrypted: encrypted.toString('hex'),
      authTag: authTag.toString('hex')
    }
  }

  decrypt(encryptedData) {
    const iv = Buffer.from(encryptedData.iv, 'hex')
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.config.encryptionKey, iv)
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'))
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedData.encrypted, 'hex')),
      decipher.final()
    ])
    return JSON.parse(decrypted.toString('utf8'))
  }

  async registerWorkflow(workflowDef) {
    const workflowId = workflowDef.id || this.generateWorkflowId(workflowDef.name)

    if (!workflowDef.name || !workflowDef.trigger || !workflowDef.steps) {
      throw new Error('Invalid workflow definition: name, trigger, and steps are required')
    }

    const encryptedWorkflow = {
      ...workflowDef,
      id: workflowId,
      encrypted: true,
      definition: this.encrypt(workflowDef),
      registeredAt: new Date().toISOString()
    }

    this.workflows.set(workflowId, encryptedWorkflow)

    logger.security('Workflow registered', {
      workflow_id: workflowId,
      workflow_name: workflowDef.name,
      trigger_type: workflowDef.trigger.type,
      step_count: workflowDef.steps.length
    })

    this.emit('workflow:registered', { workflowId, workflowDef })
    return workflowId
  }

  async executeWorkflow(workflowId, triggerData = {}, options = {}) {
    const workflow = this.workflows.get(workflowId)
    if (!workflow) {
      throw new Error(`Workflow not found: ${workflowId}`)
    }

    const workflowDef = this.decrypt(workflow.definition)
    const executionId = this.generateExecutionId()

    const execution = {
      id: executionId,
      workflowId,
      status: 'running',
      currentStep: 0,
      startTime: Date.now(),
      triggerData: this.encrypt(triggerData),
      context: this.encrypt({}),
      steps: [],
      retryCount: 0,
      options
    }

    this.executions.set(executionId, execution)

    logger.security('Workflow execution started', {
      execution_id: executionId,
      workflow_id: workflowId,
      workflow_name: workflowDef.name
    })

    this.emit('execution:started', { executionId, workflowId })

    try {
      await this.runWorkflowSteps(executionId, workflowDef)
      execution.status = 'completed'
      execution.endTime = Date.now()

      logger.security('Workflow execution completed', {
        execution_id: executionId,
        duration: execution.endTime - execution.startTime
      })

      this.emit('execution:completed', { executionId, workflowId })

    } catch (error) {
      execution.status = 'failed'
      execution.endTime = Date.now()
      execution.error = error.message

      logger.error('Workflow execution failed', {
        execution_id: executionId,
        error: error.message,
        stack: error.stack
      })

      this.emit('execution:failed', { executionId, workflowId, error })
      throw error
    }

    return executionId
  }

  async runWorkflowSteps(executionId, workflowDef) {
    const execution = this.executions.get(executionId)

    for (let i = 0; i < workflowDef.steps.length; i++) {
      const step = workflowDef.steps[i]
      execution.currentStep = i

      await this.executeStep(executionId, step, i)
    }
  }

  async executeStep(executionId, stepDef, stepIndex) {
    const execution = this.executions.get(executionId)
    const stepExecution = {
      index: stepIndex,
      name: stepDef.name,
      type: stepDef.type,
      startTime: Date.now(),
      status: 'running'
    }

    execution.steps[stepIndex] = stepExecution

    logger.debug('Executing workflow step', {
      execution_id: executionId,
      step_index: stepIndex,
      step_name: stepDef.name,
      step_type: stepDef.type
    })

    this.emit('step:started', { executionId, stepIndex, stepDef })

    try {
      // Execute step with timeout
      const result = await this.executeStepWithTimeout(executionId, stepDef)

      stepExecution.status = 'completed'
      stepExecution.endTime = Date.now()
      stepExecution.result = this.encrypt(result)

      this.emit('step:completed', { executionId, stepIndex, result })

    } catch (error) {
      stepExecution.status = 'failed'
      stepExecution.endTime = Date.now()
      stepExecution.error = error.message

      // Retry logic
      if (execution.retryCount < this.config.maxRetries && stepDef.retryable !== false) {
        execution.retryCount++
        logger.warn('Step failed, retrying', {
          execution_id: executionId,
          step_index: stepIndex,
          retry_count: execution.retryCount,
          error: error.message
        })

        await new Promise(resolve => setTimeout(resolve, 1000 * execution.retryCount))
        return this.executeStep(executionId, stepDef, stepIndex)
      }

      this.emit('step:failed', { executionId, stepIndex, error })
      throw error
    }
  }

  async executeStepWithTimeout(executionId, stepDef) {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`Step timeout after ${this.config.stepTimeout}ms`))
      }, this.config.stepTimeout)

      this.executeStepFunction(executionId, stepDef)
        .then(result => {
          clearTimeout(timeout)
          resolve(result)
        })
        .catch(error => {
          clearTimeout(timeout)
          reject(error)
        })
    })
  }

  async executeStepFunction(executionId, stepDef) {
    const execution = this.executions.get(executionId)
    const context = this.decrypt(execution.context)
    const triggerData = this.decrypt(execution.triggerData)

    // Step function execution based on type
    switch (stepDef.type) {
    case 'scan':
      return await this.executeScanStep(stepDef, context, triggerData)
    case 'fix':
      return await this.executeFixStep(stepDef, context, triggerData)
    case 'test':
      return await this.executeTestStep(stepDef, context, triggerData)
    case 'deploy':
      return await this.executeDeployStep(stepDef, context, triggerData)
    case 'notify':
      return await this.executeNotifyStep(stepDef, context, triggerData)
    case 'audit':
      return await this.executeAuditStep(stepDef, context, triggerData)
    case 'custom':
      return await this.executeCustomStep(stepDef, context, triggerData)
    default:
      throw new Error(`Unknown step type: ${stepDef.type}`)
    }
  }

  async executeScanStep(stepDef, context, triggerData) {
    logger.info('Executing scan step', { step_name: stepDef.name })
    // Implement vulnerability scanning logic
    return { scanned: true, vulnerabilities: [] }
  }

  async executeFixStep(stepDef, context, triggerData) {
    logger.info('Executing fix step', { step_name: stepDef.name })
    // Implement vulnerability fixing logic
    return { fixed: true, patches: [] }
  }

  async executeTestStep(stepDef, context, triggerData) {
    logger.info('Executing test step', { step_name: stepDef.name })
    // Implement testing logic
    return { tested: true, results: 'passed' }
  }

  async executeDeployStep(stepDef, context, triggerData) {
    logger.info('Executing deploy step', { step_name: stepDef.name })
    // Implement deployment logic
    return { deployed: true, version: 'v1.0.0' }
  }

  async executeNotifyStep(stepDef, context, triggerData) {
    logger.info('Executing notify step', { step_name: stepDef.name })
    // Implement notification logic
    return { notified: true, recipients: [] }
  }

  async executeAuditStep(stepDef, context, triggerData) {
    logger.info('Executing audit step', { step_name: stepDef.name })
    // Implement audit logging
    return { audited: true, compliance: 'passed' }
  }

  async executeCustomStep(stepDef, context, triggerData) {
    logger.info('Executing custom step', { step_name: stepDef.name })

    if (typeof stepDef.handler === 'function') {
      return await stepDef.handler({ context, triggerData, stepDef })
    }

    throw new Error('Custom step requires handler function')
  }

  generateWorkflowId(name) {
    return `wf_${name.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase()}_${Date.now()}`
  }

  generateExecutionId() {
    return `exec_${crypto.randomBytes(8).toString('hex')}`
  }

  getWorkflow(workflowId) {
    const workflow = this.workflows.get(workflowId)
    if (!workflow) {return null}

    return {
      ...workflow,
      definition: this.decrypt(workflow.definition)
    }
  }

  getExecution(executionId) {
    const execution = this.executions.get(executionId)
    if (!execution) {return null}

    return {
      ...execution,
      triggerData: this.decrypt(execution.triggerData),
      context: this.decrypt(execution.context)
    }
  }

  listWorkflows() {
    return Array.from(this.workflows.keys())
  }

  listExecutions(workflowId = null) {
    const executions = Array.from(this.executions.values())
    if (workflowId) {
      return executions.filter(exec => exec.workflowId === workflowId)
    }
    return executions
  }

  async stopExecution(executionId) {
    const execution = this.executions.get(executionId)
    if (!execution) {
      throw new Error(`Execution not found: ${executionId}`)
    }

    execution.status = 'stopped'
    execution.endTime = Date.now()

    logger.security('Workflow execution stopped', { execution_id: executionId })
    this.emit('execution:stopped', { executionId })
  }

  async replayExecution(executionId, fromStep = 0) {
    const execution = this.executions.get(executionId)
    if (!execution) {
      throw new Error(`Execution not found: ${executionId}`)
    }

    const workflow = this.workflows.get(execution.workflowId)
    const workflowDef = this.decrypt(workflow.definition)

    execution.status = 'running'
    execution.currentStep = fromStep
    execution.retryCount = 0

    logger.security('Replaying workflow execution', {
      execution_id: executionId,
      from_step: fromStep
    })

    this.emit('execution:replaying', { executionId, fromStep })

    try {
      const stepsToRun = workflowDef.steps.slice(fromStep)
      for (let i = 0; i < stepsToRun.length; i++) {
        await this.executeStep(executionId, stepsToRun[i], fromStep + i)
      }

      execution.status = 'completed'
      execution.endTime = Date.now()

    } catch (error) {
      execution.status = 'failed'
      execution.error = error.message
      throw error
    }
  }
}

module.exports = SecureFlowEngine