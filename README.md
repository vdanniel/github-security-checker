# GitHub Security Checker

> ⚠️ **Disclaimer**: This is an unofficial, community-built tool and is not affiliated with, endorsed by, or supported by GitHub, Inc.

A comprehensive tool for scanning GitHub repositories for security configuration issues and best practices. Provides actionable recommendations and SOC 2 compliance reports.

## Features

- **Security Scanning**: 40+ checks across branch protection, security features, access controls, and repository settings
- **Recommendations**: Provides specific mitigation steps with documentation links for each finding
- **SOC 2 Reports**: Generates compliance reports mapped to SOC 2 Trust Services Criteria
- **Multiple Interfaces**: CLI, MCP Server (for AI assistants), and Web Dashboard

## Security Checks (40+)

### Branch Protection (12 checks)
| Check | Severity | Description |
|-------|----------|-------------|
| Branch protection enabled | Critical | Verifies protection rules exist on default branch |
| Required PR reviews | High | Requires pull request reviews before merging |
| Dismiss stale reviews | Medium | Dismisses approvals when new commits are pushed |
| Code owner reviews | Medium | Requires review from code owners |
| Required reviewers count | Medium | Enforces minimum number of reviewers (recommended: 2) |
| Admin bypass restrictions | High | Prevents administrators from bypassing rules |
| Required status checks | High | Requires CI/CD checks to pass before merging |
| Force push restrictions | High | Prevents force pushes that rewrite history |
| Branch deletion restrictions | Medium | Prevents deletion of protected branches |
| Conversation resolution | Low | Requires all review comments to be resolved |
| Signed commits required | Medium | Requires GPG/SSH signed commits |
| Linear history required | Low | Enforces squash or rebase merging |

### Security Features (9 checks)
| Check | Severity | Description |
|-------|----------|-------------|
| Security policy (SECURITY.md) | Medium | Vulnerability reporting instructions |
| Dependabot alerts | High | Vulnerability alerts for dependencies |
| Dependabot config | Medium | Automatic dependency version updates |
| Code scanning (CodeQL) | High | Static analysis for security vulnerabilities |
| Secret scanning | High | Detects accidentally committed secrets |
| Push protection | Info | Blocks commits containing secrets |
| Critical vulnerability alerts | Critical | Unresolved critical Dependabot alerts |
| High vulnerability alerts | High | Unresolved high severity alerts |
| Private vulnerability reporting | Info | GitHub Security Advisories enabled |

### Access Control (8 checks)
| Check | Severity | Description |
|-------|----------|-------------|
| Public repository warning | Info | Alerts when repo is publicly accessible |
| Administrator count | Medium | Flags excessive admin access (>5 users) |
| Outside collaborators | Info | Tracks non-org members with write access |
| Deploy keys with write access | Medium | Identifies deploy keys that can push |
| Old deploy keys | Low | Flags deploy keys older than 1 year |
| Insecure webhook URLs | High | Webhooks using HTTP instead of HTTPS |
| Webhooks without secrets | Medium | Webhooks lacking payload validation |
| Webhook configuration audit | Info | Reviews all webhook configurations |

### Repository Settings (14 checks)
| Check | Severity | Description |
|-------|----------|-------------|
| Wiki on public repo | Info | Wiki enabled and publicly accessible |
| Issues disabled | Low | GitHub Issues disabled |
| Legacy branch name | Info | Using "master" instead of "main" |
| README file | Low | Repository documentation |
| LICENSE file | Low | License terms for the project |
| CODEOWNERS file | Medium | Automatic review assignment |
| GitHub Actions permissions | Medium | Unrestricted Actions allowed |
| .gitignore file | Low | Prevents accidental sensitive file commits |
| GITHUB_TOKEN permissions | High | Default token has write permissions |
| Actions can approve PRs | Medium | Workflows can approve pull requests |
| Private repo forking | Medium | Forking allowed for private repos |
| Merge strategies | Info | All merge types allowed |
| Auto-delete branches | Low | Merged branches not auto-deleted |
| Unprotected environments | Medium | Deployment environments without protection rules |

## Installation

```bash
# Clone the repository
git clone https://github.com/vdanniel/github-security-checker.git
cd github-security-checker

# Install dependencies
npm install

# Build all packages
npm run build
```

## Usage

### CLI

```bash
# Set your GitHub token
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx

# Interactive scan (select repos)
npx @ghsec/cli scan

# Scan specific repos
npx @ghsec/cli scan -r owner/repo1 owner/repo2

# Scan all repos in an org
npx @ghsec/cli scan -o my-organization

# Generate SOC 2 report
npx @ghsec/cli report -r owner/repo1 owner/repo2 --output soc2-report.md

# Output as JSON
npx @ghsec/cli scan -r owner/repo --json --output results.json
```

### MCP Server (for Kiro/AI Assistants)

Add to your `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "github-security": {
      "command": "node",
      "args": ["path/to/github-security-checker/packages/mcp/dist/index.js"],
      "env": {
        "GITHUB_TOKEN": "ghp_xxxxxxxxxxxx"
      }
    }
  }
}
```

Available MCP tools:
- `list_repos` - List available repositories
- `scan_repo` - Scan a single repository
- `scan_multiple_repos` - Scan multiple repositories
- `generate_soc2_report` - Generate SOC 2 compliance report
- `get_recommendations` - Get detailed fix instructions

### Web Dashboard

```bash
# Start the development server
cd packages/web
npm run dev

# Open http://localhost:3000
```

Features:
- Enter GitHub token and repository list
- Visual scan results with severity indicators
- Expandable findings with recommendations
- Summary statistics and scores

## SOC 2 Control Mapping

| Control | Description | Checks |
|---------|-------------|--------|
| CC6.1 | Logical Access Controls | Branch protection, admin access, deploy keys, GITHUB_TOKEN permissions |
| CC6.2 | User Access Management | Collaborator permissions, outside collaborators |
| CC6.7 | Data Transmission Protection | Webhook HTTPS, secret scanning, push protection |
| CC7.1 | Vulnerability Management | Dependabot, code scanning, dependency alerts |
| CC7.4 | Security Incident Response | Security policy, vulnerability reporting |
| CC8.1 | Change Management | PR reviews, status checks, code owners, signed commits |

## Security Score

Each repository receives a score from 0-100 based on findings:

| Severity | Point Deduction |
|----------|-----------------|
| Critical | -25 points |
| High | -15 points |
| Medium | -8 points |
| Low | -3 points |
| Info | 0 points |

**Score Interpretation:**
- 90-100: Excellent security posture
- 70-89: Good, minor improvements needed
- 50-69: Fair, several issues to address
- Below 50: Poor, immediate attention required

## GitHub Token Permissions

Required scopes for your Personal Access Token:

**Classic Token:**
- `repo` - Full control of private repositories
- `read:org` - Read org membership (for org scanning)
- `security_events` - Read security events

**Fine-grained Token:**
- Repository access: All repositories (or select specific ones)
- Permissions:
  - Actions: Read
  - Administration: Read
  - Contents: Read
  - Dependabot alerts: Read
  - Environments: Read
  - Metadata: Read
  - Secret scanning alerts: Read
  - Security events: Read
  - Webhooks: Read

## Project Structure

```
github-security-checker/
├── .github/
│   └── workflows/
│       ├── vscode-extension.yml  # Build & publish VS Code extension
│       └── packages.yml          # Build & test core packages
├── packages/
│   ├── core/          # Core scanning logic and types
│   ├── cli/           # Command-line interface
│   ├── mcp/           # MCP server for AI assistants
│   ├── vscode/        # VS Code extension
│   └── web/           # Next.js web dashboard
├── package.json       # Workspace configuration
└── README.md
```

## VS Code Extension

Install from [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=DanielSurendran.github-security-checker) or [Open VSX](https://open-vsx.org/).

Commands:
- `GitHub Security: Connect to GitHub` - Authenticate with GitHub
- `GitHub Security: Scan Repositories` - Run security scan
- `GitHub Security: Show Results` - View scan results
- `GitHub Security: Generate SOC 2 Report` - Generate compliance report
- `GitHub Security: Fix Finding` - Apply recommended fix

## CI/CD

The project uses GitHub Actions for continuous integration:

- **vscode-extension.yml** - Builds and publishes the VS Code extension to VS Code Marketplace and Open VSX on pushes to main
- **packages.yml** - Builds, lints, and tests core packages on every push/PR

### Required Secrets

| Secret | Description |
|--------|-------------|
| `VSCE_PAT` | Personal Access Token for VS Code Marketplace |
| `OVSX_PAT` | Personal Access Token for Open VSX Registry |

## Development

```bash
# Build core package
npm run build -w @ghsec/core

# Run web app in development
npm run dev -w @ghsec/web

# Run MCP server in development
npm run dev -w @ghsec/mcp
```

## Roadmap

- [ ] Auto-fix capabilities for common issues
- [ ] GitHub App integration (no PAT required)
- [ ] Organization-wide scanning dashboard
- [ ] Scheduled scans with notifications
- [ ] Custom rule definitions
- [ ] GitHub Rulesets support (new branch protection)
- [ ] Export to CSV/PDF formats

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## License

MIT
