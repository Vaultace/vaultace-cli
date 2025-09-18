/**
 * Vaultace SecureFlow - Encrypted State Management
 * Secure, persistent state for workflow executions
 */

const crypto = require('crypto')
const fs = require('fs-extra')
const path = require('path')
const os = require('os')
const logger = require('../../utils/logger')

class EncryptedStateManager {
  constructor(options = {}) {
    this.stateDir = options.stateDir || path.join(os.homedir(), '.vaultace', 'workflows', 'state')
    this.algorithm = 'aes-256-gcm'
    this.keyDerivationSalt = options.salt || crypto.randomBytes(32)
    this.compressionEnabled = options.compression !== false
    this.maxStateSize = options.maxStateSize || 50 * 1024 * 1024 // 50MB
    this.encryptionKey = options.encryptionKey || this.loadOrGenerateKey()

    this.init()
  }

  async init() {
    await fs.ensureDir(this.stateDir)
    await fs.ensureDir(path.join(this.stateDir, 'executions'))
    await fs.ensureDir(path.join(this.stateDir, 'workflows'))
    await fs.ensureDir(path.join(this.stateDir, 'snapshots'))

    logger.debug('State manager initialized', {
      state_dir: this.stateDir,
      compression: this.compressionEnabled
    })
  }

  loadOrGenerateKey() {
    const keyFile = path.join(os.homedir(), '.vaultace', 'secureflow.key')

    try {
      if (fs.existsSync(keyFile)) {
        const keyData = fs.readFileSync(keyFile)
        return crypto.pbkdf2Sync(keyData, this.keyDerivationSalt, 100000, 32, 'sha512')
      }
    } catch (error) {
      logger.warn('Failed to load encryption key, generating new one', {
        error: error.message
      })
    }

    // Generate new key
    const newKey = crypto.randomBytes(32)
    try {
      fs.ensureDirSync(path.dirname(keyFile))
      fs.writeFileSync(keyFile, newKey, { mode: 0o600 })
    } catch (error) {
      logger.error('Failed to save encryption key', { error: error.message })
    }

    return crypto.pbkdf2Sync(newKey, this.keyDerivationSalt, 100000, 32, 'sha512')
  }

  encrypt(data) {
    try {
      const iv = crypto.randomBytes(16)
      const cipher = crypto.createCipheriv(this.algorithm, this.encryptionKey, iv)
      cipher.setAAD(Buffer.from('vaultace-secureflow'))

      let serialized = JSON.stringify(data)

      // Optional compression
      if (this.compressionEnabled && serialized.length > 1024) {
        const zlib = require('zlib')
        serialized = zlib.gzipSync(serialized).toString('base64')
        data._compressed = true
      }

      const encrypted = Buffer.concat([
        cipher.update(serialized, 'utf8'),
        cipher.final()
      ])

      const authTag = cipher.getAuthTag()

      return {
        iv: iv.toString('hex'),
        encrypted: encrypted.toString('hex'),
        authTag: authTag.toString('hex'),
        algorithm: this.algorithm,
        compressed: data._compressed || false,
        timestamp: Date.now()
      }
    } catch (error) {
      logger.error('State encryption failed', { error: error.message })
      throw new Error('Failed to encrypt state data')
    }
  }

  decrypt(encryptedData) {
    try {
      const iv = Buffer.from(encryptedData.iv, 'hex')
      const decipher = crypto.createDecipheriv(this.algorithm, this.encryptionKey, iv)
      decipher.setAAD(Buffer.from('vaultace-secureflow'))
      decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'))

      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encryptedData.encrypted, 'hex')),
        decipher.final()
      ])

      let serialized = decrypted.toString('utf8')

      // Handle decompression
      if (encryptedData.compressed) {
        const zlib = require('zlib')
        serialized = zlib.gunzipSync(Buffer.from(serialized, 'base64')).toString('utf8')
      }

      return JSON.parse(serialized)
    } catch (error) {
      logger.error('State decryption failed', { error: error.message })
      throw new Error('Failed to decrypt state data')
    }
  }

  async saveExecutionState(executionId, state) {
    try {
      const stateSize = JSON.stringify(state).length
      if (stateSize > this.maxStateSize) {
        throw new Error(`State size ${stateSize} exceeds maximum ${this.maxStateSize}`)
      }

      const encryptedState = this.encrypt({
        ...state,
        _metadata: {
          executionId,
          savedAt: new Date().toISOString(),
          version: '1.0',
          size: stateSize
        }
      })

      const stateFile = path.join(this.stateDir, 'executions', `${executionId}.state`)
      await fs.writeFile(stateFile, JSON.stringify(encryptedState, null, 2))

      logger.debug('Execution state saved', {
        execution_id: executionId,
        state_size: stateSize,
        compressed: encryptedState.compressed
      })

      return true
    } catch (error) {
      logger.error('Failed to save execution state', {
        execution_id: executionId,
        error: error.message
      })
      throw error
    }
  }

  async loadExecutionState(executionId) {
    try {
      const stateFile = path.join(this.stateDir, 'executions', `${executionId}.state`)

      if (!await fs.pathExists(stateFile)) {
        return null
      }

      const encryptedData = JSON.parse(await fs.readFile(stateFile, 'utf8'))
      const state = this.decrypt(encryptedData)

      logger.debug('Execution state loaded', {
        execution_id: executionId,
        saved_at: state._metadata?.savedAt
      })

      return state
    } catch (error) {
      logger.error('Failed to load execution state', {
        execution_id: executionId,
        error: error.message
      })
      return null
    }
  }

  async saveWorkflowDefinition(workflowId, definition) {
    try {
      const encryptedDefinition = this.encrypt({
        ...definition,
        _metadata: {
          workflowId,
          savedAt: new Date().toISOString(),
          version: '1.0'
        }
      })

      const defFile = path.join(this.stateDir, 'workflows', `${workflowId}.def`)
      await fs.writeFile(defFile, JSON.stringify(encryptedDefinition, null, 2))

      logger.debug('Workflow definition saved', { workflow_id: workflowId })
      return true
    } catch (error) {
      logger.error('Failed to save workflow definition', {
        workflow_id: workflowId,
        error: error.message
      })
      throw error
    }
  }

  async loadWorkflowDefinition(workflowId) {
    try {
      const defFile = path.join(this.stateDir, 'workflows', `${workflowId}.def`)

      if (!await fs.pathExists(defFile)) {
        return null
      }

      const encryptedData = JSON.parse(await fs.readFile(defFile, 'utf8'))
      const definition = this.decrypt(encryptedData)

      logger.debug('Workflow definition loaded', { workflow_id: workflowId })
      return definition
    } catch (error) {
      logger.error('Failed to load workflow definition', {
        workflow_id: workflowId,
        error: error.message
      })
      return null
    }
  }

  async createSnapshot(executionId, stepIndex, state) {
    try {
      const snapshotId = `${executionId}_step_${stepIndex}_${Date.now()}`
      const encryptedSnapshot = this.encrypt({
        ...state,
        _metadata: {
          snapshotId,
          executionId,
          stepIndex,
          createdAt: new Date().toISOString()
        }
      })

      const snapshotFile = path.join(this.stateDir, 'snapshots', `${snapshotId}.snap`)
      await fs.writeFile(snapshotFile, JSON.stringify(encryptedSnapshot, null, 2))

      logger.debug('State snapshot created', {
        snapshot_id: snapshotId,
        execution_id: executionId,
        step_index: stepIndex
      })

      return snapshotId
    } catch (error) {
      logger.error('Failed to create state snapshot', {
        execution_id: executionId,
        step_index: stepIndex,
        error: error.message
      })
      throw error
    }
  }

  async restoreSnapshot(snapshotId) {
    try {
      const snapshotFile = path.join(this.stateDir, 'snapshots', `${snapshotId}.snap`)

      if (!await fs.pathExists(snapshotFile)) {
        throw new Error(`Snapshot not found: ${snapshotId}`)
      }

      const encryptedData = JSON.parse(await fs.readFile(snapshotFile, 'utf8'))
      const snapshot = this.decrypt(encryptedData)

      logger.debug('State snapshot restored', {
        snapshot_id: snapshotId,
        execution_id: snapshot._metadata?.executionId
      })

      return snapshot
    } catch (error) {
      logger.error('Failed to restore state snapshot', {
        snapshot_id: snapshotId,
        error: error.message
      })
      throw error
    }
  }

  async listExecutions() {
    try {
      const executionDir = path.join(this.stateDir, 'executions')
      const files = await fs.readdir(executionDir)

      return files
        .filter(file => file.endsWith('.state'))
        .map(file => path.basename(file, '.state'))
    } catch (error) {
      logger.error('Failed to list executions', { error: error.message })
      return []
    }
  }

  async listWorkflows() {
    try {
      const workflowDir = path.join(this.stateDir, 'workflows')
      const files = await fs.readdir(workflowDir)

      return files
        .filter(file => file.endsWith('.def'))
        .map(file => path.basename(file, '.def'))
    } catch (error) {
      logger.error('Failed to list workflows', { error: error.message })
      return []
    }
  }

  async listSnapshots(executionId = null) {
    try {
      const snapshotDir = path.join(this.stateDir, 'snapshots')
      const files = await fs.readdir(snapshotDir)

      let snapshots = files
        .filter(file => file.endsWith('.snap'))
        .map(file => path.basename(file, '.snap'))

      if (executionId) {
        snapshots = snapshots.filter(snapshot =>
          snapshot.startsWith(`${executionId}_`))
      }

      return snapshots
    } catch (error) {
      logger.error('Failed to list snapshots', { error: error.message })
      return []
    }
  }

  async deleteExecutionState(executionId) {
    try {
      const stateFile = path.join(this.stateDir, 'executions', `${executionId}.state`)
      await fs.remove(stateFile)

      // Also remove associated snapshots
      const snapshots = await this.listSnapshots(executionId)
      for (const snapshotId of snapshots) {
        await this.deleteSnapshot(snapshotId)
      }

      logger.debug('Execution state deleted', { execution_id: executionId })
      return true
    } catch (error) {
      logger.error('Failed to delete execution state', {
        execution_id: executionId,
        error: error.message
      })
      return false
    }
  }

  async deleteWorkflowDefinition(workflowId) {
    try {
      const defFile = path.join(this.stateDir, 'workflows', `${workflowId}.def`)
      await fs.remove(defFile)

      logger.debug('Workflow definition deleted', { workflow_id: workflowId })
      return true
    } catch (error) {
      logger.error('Failed to delete workflow definition', {
        workflow_id: workflowId,
        error: error.message
      })
      return false
    }
  }

  async deleteSnapshot(snapshotId) {
    try {
      const snapshotFile = path.join(this.stateDir, 'snapshots', `${snapshotId}.snap`)
      await fs.remove(snapshotFile)

      logger.debug('Snapshot deleted', { snapshot_id: snapshotId })
      return true
    } catch (error) {
      logger.error('Failed to delete snapshot', {
        snapshot_id: snapshotId,
        error: error.message
      })
      return false
    }
  }

  async getStateStatistics() {
    try {
      const executions = await this.listExecutions()
      const workflows = await this.listWorkflows()
      const snapshots = await this.listSnapshots()

      // Calculate total size
      let totalSize = 0
      const dirs = ['executions', 'workflows', 'snapshots']

      for (const dir of dirs) {
        const dirPath = path.join(this.stateDir, dir)
        const files = await fs.readdir(dirPath)

        for (const file of files) {
          const filePath = path.join(dirPath, file)
          const stats = await fs.stat(filePath)
          totalSize += stats.size
        }
      }

      return {
        executions: executions.length,
        workflows: workflows.length,
        snapshots: snapshots.length,
        total_size_bytes: totalSize,
        total_size_mb: Math.round(totalSize / (1024 * 1024) * 100) / 100,
        state_directory: this.stateDir
      }
    } catch (error) {
      logger.error('Failed to get state statistics', { error: error.message })
      return null
    }
  }

  async cleanup(olderThanDays = 30) {
    try {
      const cutoffTime = Date.now() - (olderThanDays * 24 * 60 * 60 * 1000)
      let cleanedCount = 0

      const dirs = [
        { path: path.join(this.stateDir, 'executions'), ext: '.state' },
        { path: path.join(this.stateDir, 'snapshots'), ext: '.snap' }
      ]

      for (const dir of dirs) {
        const files = await fs.readdir(dir.path)

        for (const file of files) {
          if (!file.endsWith(dir.ext)) {continue}

          const filePath = path.join(dir.path, file)
          const stats = await fs.stat(filePath)

          if (stats.mtime.getTime() < cutoffTime) {
            await fs.remove(filePath)
            cleanedCount++
          }
        }
      }

      logger.info('State cleanup completed', {
        cleaned_files: cleanedCount,
        older_than_days: olderThanDays
      })

      return cleanedCount
    } catch (error) {
      logger.error('State cleanup failed', { error: error.message })
      throw error
    }
  }
}

module.exports = EncryptedStateManager