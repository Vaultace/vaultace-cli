/**
 * Local Scanner Service
 * Performs security vulnerability detection on local repositories
 */

const fs = require('fs-extra')
const path = require('path')
const { glob } = require('glob')
const ignore = require('ignore')
const crypto = require('crypto')
const LLMGuardrails = require('./llm-guardrails')

class LocalScanner {
  constructor(options = {}) {
    this.path = options.path || '.'
    this.severity = options.severity || 'medium'
    this.exclude = options.exclude || []
    this.include = options.include || []
    this.respectGitignore = options.respectGitignore !== false
    this.aiPatterns = options.aiPatterns || false
    this.framework = options.framework
    this.verbose = options.verbose || false
    
    this.vulnerabilities = []
    this.stats = {
      filesScanned: 0,
      linesScanned: 0,
      scanDuration: 0,
      aiPatternsFound: 0
    }

    // Initialize LLM Guardrails
    this.guardrails = new LLMGuardrails({
      verbose: this.verbose,
      severityThreshold: this.severity
    })
  }

  async scan() {
    const startTime = Date.now()
    
    try {
      // Get files to scan
      const files = await this.getFilesToScan()
      
      if (this.verbose) {
        console.log(`Found ${files.length} files to scan`)
      }
      
      // Scan each file
      for (const file of files) {
        await this.scanFile(file)
      }
      
      this.stats.scanDuration = Date.now() - startTime
      
      return {
        vulnerabilities: this.vulnerabilities,
        stats: this.stats,
        scanId: crypto.randomUUID(),
        timestamp: new Date().toISOString()
      }
      
    } catch (error) {
      throw new Error(`Scan failed: ${error.message}`)
    }
  }

  async getFilesToScan() {
    const files = []
    const ig = ignore()
    
    // Load .gitignore if respecting it
    if (this.respectGitignore) {
      try {
        const gitignorePath = path.join(this.path, '.gitignore')
        if (await fs.exists(gitignorePath)) {
          const gitignoreContent = await fs.readFile(gitignorePath, 'utf8')
          ig.add(gitignoreContent)
        }
      } catch (error) {
        // Continue if .gitignore can't be read
      }
    }
    
    // Add exclude patterns
    if (this.exclude.length > 0) {
      ig.add(this.exclude)
    }
    
    // Default exclusions
    ig.add([
      'node_modules/**',
      '.git/**',
      '.vscode/**',
      '.idea/**',
      '*.log',
      '*.tmp',
      'dist/**',
      'build/**',
      '__pycache__/**',
      '*.pyc',
      '.pytest_cache/**'
    ])
    
    // Get all files
    const globPattern = this.include.length > 0 
      ? `{${this.include.join(',')}}` 
      : '**/*'
    
    const allFiles = await glob(globPattern, { 
      cwd: this.path, 
      nodir: true,
      ignore: ['node_modules/**', '.git/**']
    })
    
    // Filter files
    const filteredFiles = allFiles.filter(file => {
      // Apply ignore rules
      if (ig.ignores(file)) {return false}
      
      // Only scan code files
      const ext = path.extname(file).toLowerCase()
      const codeExtensions = [
        '.js', '.jsx', '.ts', '.tsx',
        '.py', '.rb', '.php', '.java',
        '.go', '.rs', '.cpp', '.c',
        '.cs', '.swift', '.kt', '.scala',
        '.vue', '.svelte', '.html', '.css',
        '.yaml', '.yml', '.json', '.xml',
        '.sql', '.sh', '.bash', '.ps1'
      ]
      
      return codeExtensions.includes(ext)
    })
    
    return filteredFiles.map(file => path.join(this.path, file))
  }

  async scanFile(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf8')
      const lines = content.split('\n')
      
      this.stats.filesScanned++
      this.stats.linesScanned += lines.length
      
      // Detect vulnerabilities
      const fileVulnerabilities = this.detectVulnerabilities(filePath, content, lines)
      this.vulnerabilities.push(...fileVulnerabilities)

      // Check for LLM-related vulnerabilities using guardrails
      const llmVulnerabilities = await this.detectLLMVulnerabilities(filePath, content)
      this.vulnerabilities.push(...llmVulnerabilities)
      
    } catch (error) {
      if (this.verbose) {
        console.warn(`Could not scan file ${filePath}: ${error.message}`)
      }
    }
  }

  detectVulnerabilities(filePath, content, lines) {
    const vulnerabilities = []
    const fileName = path.basename(filePath)
    const ext = path.extname(filePath).toLowerCase()
    
    // Security patterns to detect
    const patterns = [
      // SQL Injection
      {
        pattern: /\$\{[^}]*\}.*(?:SELECT|INSERT|UPDATE|DELETE)/i,
        type: 'sql_injection',
        severity: 'high',
        message: 'Potential SQL injection vulnerability'
      },
      
      // XSS
      {
        pattern: /innerHTML\s*=.*\$\{|dangerouslySetInnerHTML/i,
        type: 'xss',
        severity: 'medium',
        message: 'Potential XSS vulnerability'
      },
      
      // Hardcoded secrets
      {
        pattern: /(password|secret|key|token)\s*[:=]\s*['"]\w{8,}/i,
        type: 'exposed_secret',
        severity: 'critical',
        message: 'Hardcoded secret detected'
      },
      
      // Command injection
      {
        pattern: /exec\(.*\$\{|system\(.*\$\{|eval\(.*\$\{/i,
        type: 'command_injection',
        severity: 'critical',
        message: 'Potential command injection'
      },
      
      // Path traversal
      {
        pattern: /\.\.\//,
        type: 'path_traversal',
        severity: 'medium',
        message: 'Potential path traversal vulnerability'
      },

      // MLOps-specific vulnerabilities
      {
        pattern: /(model\.load|pickle\.load|joblib\.load)\s*\([^)]*untrusted|user.*input/i,
        type: 'model_deserialization',
        severity: 'critical',
        message: 'Unsafe model deserialization from untrusted source'
      },

      {
        pattern: /(torch\.load|tf\.keras\.models\.load_model)\s*\([^)]*http|url|remote/i,
        type: 'remote_model_loading',
        severity: 'high',
        message: 'Loading ML model from remote/untrusted source'
      },

      {
        pattern: /train.*data.*=.*input|user.*data.*training/i,
        type: 'data_poisoning_risk',
        severity: 'high',
        message: 'Potential data poisoning - user input in training data'
      },

      {
        pattern: /(membership.*inference|model.*inversion|extraction.*attack)/i,
        type: 'privacy_attack_vector',
        severity: 'medium',
        message: 'Potential ML privacy attack implementation'
      },

      {
        pattern: /backdoor.*trigger|hidden.*activation|adversarial.*sample/i,
        type: 'adversarial_ml',
        severity: 'high',
        message: 'Potential adversarial ML attack implementation'
      }
    ]
    
    // AI-specific patterns
    if (this.aiPatterns) {
      patterns.push(
        {
          pattern: /\/\*\s*AI\s*generated|AI-generated|Generated by AI/i,
          type: 'ai_generated_code',
          severity: 'info',
          message: 'AI-generated code detected'
        },
        {
          pattern: /prompt.*injection|inject.*prompt/i,
          type: 'prompt_injection',
          severity: 'high',
          message: 'Potential prompt injection vulnerability'
        }
      )
    }
    
    // Check each line
    lines.forEach((line, index) => {
      patterns.forEach(pattern => {
        if (pattern.pattern.test(line)) {
          // Skip if severity is below threshold
          const severityLevel = { 'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 }
          if (severityLevel[pattern.severity] < severityLevel[this.severity]) {
            return
          }
          
          vulnerabilities.push({
            type: pattern.type,
            severity: pattern.severity,
            message: pattern.message,
            file: path.relative(this.path, filePath),
            line: index + 1,
            code: line.trim(),
            description: this.getVulnerabilityDescription(pattern.type)
          })
          
          if (pattern.type === 'ai_generated_code') {
            this.stats.aiPatternsFound++
          }
        }
      })
    })
    
    return vulnerabilities
  }

  getVulnerabilityDescription(type) {
    const descriptions = {
      sql_injection: 'Dynamic SQL queries with user input can lead to data theft or corruption',
      xss: 'Unescaped user input in HTML can execute malicious scripts',
      exposed_secret: 'Hardcoded credentials in source code pose security risks',
      command_injection: 'Dynamic command execution can lead to system compromise',
      path_traversal: 'File path manipulation can access unauthorized files',
      ai_generated_code: 'AI-generated code may contain subtle security vulnerabilities',
      prompt_injection: 'AI prompt manipulation can bypass security controls',
      model_deserialization: 'Unsafe model loading can execute malicious code embedded in model files',
      remote_model_loading: 'Loading models from untrusted sources poses supply chain risks',
      data_poisoning_risk: 'User-controlled training data can poison model behavior',
      privacy_attack_vector: 'ML privacy attacks can extract sensitive training data',
      adversarial_ml: 'Adversarial ML techniques can manipulate model predictions'
    }
    
    return descriptions[type] || 'Security vulnerability detected'
  }

  async detectLLMVulnerabilities(filePath, content) {
    const vulnerabilities = []
    const ext = path.extname(filePath).toLowerCase()

    // Skip non-code files
    if (!['.js', '.py', '.ts', '.jsx', '.tsx'].includes(ext)) {
      return vulnerabilities
    }

    try {
      // Check for SQL queries in the content
      const sqlMatches = content.match(/(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)\s+.*?(?:;|\n|$)/gsi)
      if (sqlMatches) {
        for (const sqlQuery of sqlMatches) {
          const result = this.guardrails.sqlQueryValidator(sqlQuery)
          if (!result.valid) {
            result.violations.forEach(violation => {
              vulnerabilities.push({
                type: 'llm_guardrail_violation',
                subtype: violation.type,
                severity: violation.severity,
                message: `LLM Guardrail: ${violation.message}`,
                file: path.relative(this.path, filePath),
                code: sqlQuery.trim(),
                description: 'SQL query failed LLM guardrail validation'
              })
            })
          }
        }
      }

      // Check for potential prompt injection patterns
      const result = await this.guardrails.checkAll(content, 'prompt')
      if (result.blocked) {
        result.violations.forEach(violation => {
          if (violation.type === 'prompt_injection') {
            vulnerabilities.push({
              type: 'llm_guardrail_violation',
              subtype: violation.type,
              severity: violation.severity,
              message: `LLM Guardrail: ${violation.message}`,
              file: path.relative(this.path, filePath),
              description: violation.description || 'LLM guardrail violation detected'
            })
          }
        })
      }

      // Check for sensitive content
      if (result.violations.some(v => v.type === 'sensitive_content')) {
        const sensitiveViolations = result.violations.filter(v => v.type === 'sensitive_content')
        sensitiveViolations.forEach(violation => {
          vulnerabilities.push({
            type: 'llm_guardrail_violation',
            subtype: violation.type,
            severity: violation.severity,
            message: `LLM Guardrail: ${violation.message}`,
            file: path.relative(this.path, filePath),
            description: 'Sensitive content detected by LLM guardrails'
          })
        })
      }

    } catch (error) {
      if (this.verbose) {
        console.warn(`LLM guardrail check failed for ${filePath}: ${error.message}`)
      }
    }

    return vulnerabilities
  }
}

module.exports = LocalScanner