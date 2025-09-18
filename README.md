# VaultAce CLI

🛡️ **Open-source security toolkit for developers and security teams**

VaultAce CLI is a powerful, community-driven security tool that helps developers integrate security scanning, vulnerability analysis, and LLM safety guardrails into their development workflow.

## 🌟 What's Included (Open Source)

### 🔍 **Security Scanning**
- Vulnerability detection and analysis
- Code security assessments
- Dependency scanning with community NVD database
- Basic risk assessment and reporting

### 🛡️ **LLM Security Guardrails**
- Prompt injection detection
- Sensitive content scanning
- Inappropriate content filtering
- SQL injection validation
- Interactive testing mode for AI applications

### 📊 **Security Analytics**
- Security dashboard with key metrics
- Vulnerability trending and analysis
- Basic reporting capabilities
- Exportable results in multiple formats

### 🔄 **Workflow Automation**
- Automated security workflows
- Integration with CI/CD pipelines
- Customizable security checks
- Team collaboration features

## 🚀 Quick Start

### Installation
```bash
npm install -g @vaultace/cli
```

### Basic Usage
```bash
# Run a basic security scan
vaultace intelligence scan

# View security analytics
vaultace analytics dashboard

# Test LLM prompts for security issues
vaultace guardrails --interactive

# Run automated security workflow
vaultace workflow run security-check
```

## 📋 Available Commands

### Core Security
- `vaultace intelligence scan [target]` - Scan for vulnerabilities
- `vaultace analytics dashboard` - View security metrics
- `vaultace analytics risk` - Risk assessment
- `vaultace analytics trends` - Security trends over time

### LLM Security
- `vaultace guardrails --text "prompt"` - Test text for security issues
- `vaultace guardrails --interactive` - Interactive prompt testing
- `vaultace guardrails test <type> "text"` - Test specific guardrail

### Workflows
- `vaultace workflow list` - List available workflows
- `vaultace workflow run <name>` - Execute security workflow

## 🔧 Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run linting
npm run lint

# Build the project
npm run build
```

## 🏢 Enterprise Features

VaultAce also offers enterprise-grade features including advanced ML-powered threat intelligence, global vulnerability databases, and premium support.

**Learn more at [vaultace.co](https://vaultace.co)**

## 📜 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

We welcome contributions from the security community! Please see CONTRIBUTING.md for guidelines on how to contribute to the project.

### Ways to Contribute
- 🐛 Report bugs and security issues
- 💡 Suggest new features
- 🔧 Submit pull requests
- 📚 Improve documentation
- 🧪 Add test cases

## 🔗 Links

- **Website**: [vaultace.co](https://vaultace.co)
- **Documentation**: [docs.vaultace.co](https://docs.vaultace.co)
- **Issues**: [GitHub Issues](https://github.com/Vaultace/vaultace-cli/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Vaultace/vaultace-cli/discussions)

---

*Built with ❤️ by the VaultAce community*
