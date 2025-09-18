/**
 * CI/CD Integration Command
 * Generate CI/CD workflow templates and setup automation
 */

const { Command } = require('commander')
const chalk = require('chalk')
const inquirer = require('inquirer')
const fs = require('fs-extra')
const path = require('path')
const ora = require('ora')

const ciCommand = new Command('ci')
  .description('CI/CD integration for automated security scanning')

// Setup CI workflow
ciCommand
  .command('setup')
  .description('Setup CI/CD integration')
  .option('-p, --platform <platform>', 'CI platform (github|gitlab|jenkins|circleci)', 'github')
  .option('-f, --framework <framework>', 'project framework (react|nextjs|fastapi|django|nodejs)')
  .action(async (options) => {
    console.log(chalk.bold.cyan('🔧 Setting up Vaultace CI/CD Integration\n'))
    
    try {
      // Detect platform if not specified
      let platform = options.platform
      if (!platform) {
        if (await fs.exists('.github/workflows')) {platform = 'github'}
        else if (await fs.exists('.gitlab-ci.yml')) {platform = 'gitlab'}
        else if (await fs.exists('Jenkinsfile')) {platform = 'jenkins'}
        else if (await fs.exists('.circleci/config.yml')) {platform = 'circleci'}
      }
      
      // Detect framework if not specified
      let framework = options.framework
      if (!framework && await fs.exists('package.json')) {
        const pkg = await fs.readJSON('package.json')
        if (pkg.dependencies?.next) {framework = 'nextjs'}
        else if (pkg.dependencies?.react) {framework = 'react'}
        else {framework = 'nodejs'}
      } else if (!framework && await fs.exists('requirements.txt')) {
        const requirements = await fs.readFile('requirements.txt', 'utf8')
        if (requirements.includes('fastapi')) {framework = 'fastapi'}
        else if (requirements.includes('django')) {framework = 'django'}
        else {framework = 'python'}
      }
      
      const answers = await inquirer.prompt([
        {
          type: 'list',
          name: 'platform',
          message: 'Select CI/CD platform:',
          choices: [
            { name: 'GitHub Actions', value: 'github' },
            { name: 'GitLab CI', value: 'gitlab' },
            { name: 'Jenkins', value: 'jenkins' },
            { name: 'CircleCI', value: 'circleci' }
          ],
          default: platform
        },
        {
          type: 'list',
          name: 'framework',
          message: 'Select project framework:',
          choices: [
            { name: 'React', value: 'react' },
            { name: 'Next.js', value: 'nextjs' },
            { name: 'Node.js', value: 'nodejs' },
            { name: 'FastAPI', value: 'fastapi' },
            { name: 'Django', value: 'django' },
            { name: 'Other/Generic', value: 'generic' }
          ],
          default: framework
        },
        {
          type: 'confirm',
          name: 'failOnVuln',
          message: 'Fail build on high/critical vulnerabilities?',
          default: true
        },
        {
          type: 'input',
          name: 'scanPath',
          message: 'Path to scan (relative to repo root):',
          default: '.'
        }
      ])
      
      const spinner = ora('Generating CI/CD workflow...').start()
      
      // Generate workflow file
      const workflowContent = generateWorkflow(answers)
      const workflowPath = getWorkflowPath(answers.platform)
      
      // Create directory if needed
      await fs.ensureDir(path.dirname(workflowPath))
      
      // Write workflow file
      await fs.writeFile(workflowPath, workflowContent)
      
      spinner.succeed('CI/CD workflow generated successfully!')
      
      console.log(chalk.green('\n✅ Integration Setup Complete'))
      console.log(`${chalk.bold('Platform:')} ${answers.platform}`)
      console.log(`${chalk.bold('Framework:')} ${answers.framework}`)
      console.log(`${chalk.bold('Workflow file:')} ${workflowPath}`)
      
      console.log(chalk.blue('\n🔍 Next steps:'))
      console.log('1. Commit and push the workflow file to your repository')
      console.log('2. Set VAULTACE_API_KEY secret in your CI environment')
      console.log('3. Get API key from: https://app.vaultace.com/settings')
      
      if (answers.platform === 'github') {
        console.log(chalk.gray('4. Go to Settings > Secrets and variables > Actions'))
        console.log(chalk.gray('5. Add new repository secret: VAULTACE_API_KEY'))
      }
      
    } catch (error) {
      console.error(chalk.red(`CI setup failed: ${error.message}`))
      process.exit(1)
    }
  })

// Generate API key
ciCommand
  .command('token')
  .description('Generate API token for CI/CD')
  .action(async () => {
    console.log(chalk.cyan('🔑 CI/CD API Token Generation'))
    console.log(chalk.gray('Note: API tokens are managed through the web dashboard\n'))
    
    console.log(chalk.bold('To generate a CI/CD token:'))
    console.log('1. Go to https://app.vaultace.com/settings')
    console.log('2. Navigate to API Keys section')
    console.log('3. Click "Generate CI/CD Token"')
    console.log('4. Copy the token and add it to your CI secrets')
    
    console.log(chalk.yellow('\n⚠️ Security reminder:'))
    console.log('• Keep API tokens secure and rotate them regularly')
    console.log('• Use environment-specific tokens for different stages')
    console.log('• Never commit tokens to your repository')
  })

function getWorkflowPath(platform) {
  switch (platform) {
  case 'github':
    return '.github/workflows/vaultace-security-scan.yml'
  case 'gitlab':
    return '.gitlab-ci.yml'
  case 'jenkins':
    return 'Jenkinsfile.vaultace'
  case 'circleci':
    return '.circleci/vaultace-config.yml'
  default:
    return 'vaultace-workflow.yml'
  }
}

function generateWorkflow(config) {
  const { platform, framework, failOnVuln, scanPath } = config
  
  switch (platform) {
  case 'github':
    return generateGitHubWorkflow(framework, failOnVuln, scanPath)
  case 'gitlab':
    return generateGitLabWorkflow(framework, failOnVuln, scanPath)
  case 'jenkins':
    return generateJenkinsfile(framework, failOnVuln, scanPath)
  case 'circleci':
    return generateCircleCIWorkflow(framework, failOnVuln, scanPath)
  default:
    return generateGenericWorkflow(framework, failOnVuln, scanPath)
  }
}

function generateGitHubWorkflow(framework, failOnVuln, scanPath) {
  return `name: Vaultace Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        
    - name: Install Vaultace CLI
      run: npm install -g @vaultace/cli
      
    - name: Run Vaultace Security Scan
      env:
        VAULTACE_API_KEY: \${{ secrets.VAULTACE_API_KEY }}
      run: |
        vaultace scan ${scanPath} \\
          --remote \\
          --format sarif \\
          --output vaultace-results.sarif \\
          ${framework !== 'generic' ? `--framework ${framework}` : ''} \\
          ${failOnVuln ? '--ci' : ''}
    
    - name: Upload SARIF to GitHub
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: vaultace-results.sarif
        
    - name: Upload Scan Results
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: vaultace-scan-results
        path: vaultace-results.sarif`
}

function generateGitLabWorkflow(framework, failOnVuln, scanPath) {
  return `# Vaultace Security Scan Integration
vaultace-scan:
  stage: test
  image: node:18-alpine
  
  before_script:
    - npm install -g @vaultace/cli
    
  script:
    - |
      vaultace scan ${scanPath} \\
        --remote \\
        --format json \\
        --output vaultace-results.json \\
        ${framework !== 'generic' ? `--framework ${framework}` : ''} \\
        ${failOnVuln ? '--ci' : ''}
        
  artifacts:
    reports:
      junit: vaultace-results.json
    paths:
      - vaultace-results.json
    expire_in: 1 week
    
  only:
    - main
    - merge_requests`
}

function generateJenkinsfile(framework, failOnVuln, scanPath) {
  return `pipeline {
    agent any
    
    environment {
        VAULTACE_API_KEY = credentials('vaultace-api-key')
    }
    
    stages {
        stage('Security Scan') {
            steps {
                sh 'npm install -g @vaultace/cli'
                sh '''
                    vaultace scan ${scanPath} \\
                      --remote \\
                      --format json \\
                      --output vaultace-results.json \\
                      ${framework !== 'generic' ? `--framework ${framework}` : ''} \\
                      ${failOnVuln ? '--ci' : ''}
                '''
            }
            
            post {
                always {
                    archiveArtifacts artifacts: 'vaultace-results.json', fingerprint: true
                }
            }
        }
    }
}`
}

function generateCircleCIWorkflow(framework, failOnVuln, scanPath) {
  return `version: 2.1

orbs:
  node: circleci/node@5.1.0

jobs:
  vaultace-scan:
    docker:
      - image: cimg/node:18.0
    steps:
      - checkout
      
      - run:
          name: Install Vaultace CLI
          command: npm install -g @vaultace/cli
          
      - run:
          name: Run Security Scan
          command: |
            vaultace scan ${scanPath} \\
              --remote \\
              --format json \\
              --output vaultace-results.json \\
              ${framework !== 'generic' ? `--framework ${framework}` : ''} \\
              ${failOnVuln ? '--ci' : ''}
              
      - store_artifacts:
          path: vaultace-results.json
          destination: scan-results

workflows:
  security-check:
    jobs:
      - vaultace-scan`
}

function generateGenericWorkflow(framework, failOnVuln, scanPath) {
  return `# Vaultace Security Scan
# Add this to your CI/CD pipeline

# Install Vaultace CLI
npm install -g @vaultace/cli

# Run security scan
vaultace scan ${scanPath} \\
  --remote \\
  --format json \\
  --output vaultace-results.json \\
  ${framework !== 'generic' ? `--framework ${framework}` : ''} \\
  ${failOnVuln ? '--ci' : ''}

# The scan will:
# - Detect AI-generated security vulnerabilities
# - Upload results to Vaultace dashboard
# - ${failOnVuln ? 'Fail the build if critical/high vulnerabilities found' : 'Report vulnerabilities without failing build'}
# - Generate scan artifact for download`
}

module.exports = ciCommand