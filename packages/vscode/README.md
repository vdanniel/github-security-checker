# GitHub Security Checker

> ⚠️ **Disclaimer**: This is an unofficial, community-built tool and is not affiliated with, endorsed by, or supported by GitHub, Inc.

Scan GitHub repositories for security misconfigurations with SOC 2 compliance mapping.

## Features

- **40+ Security Checks** across branch protection, security features, access controls, and repository settings
- **SOC 2 Compliance Reports** mapped to Trust Services Criteria
- **Actionable Recommendations** with documentation links for each finding
- **Security Score** from 0-100 based on findings

## Commands

| Command | Description |
|---------|-------------|
| `GitHub Security: Connect to GitHub` | Authenticate with your GitHub token |
| `GitHub Security: Scan Repositories` | Run security scan on selected repos |
| `GitHub Security: Show Results` | View scan results in a panel |
| `GitHub Security: Generate SOC 2 Report` | Generate compliance report |
| `GitHub Security: Fix Finding` | Apply recommended fix |
| `GitHub Security: Disconnect` | Clear stored credentials |

## Security Checks

### Branch Protection (12 checks)
- Branch protection enabled
- Required PR reviews
- Dismiss stale reviews
- Code owner reviews
- Required reviewers count
- Admin bypass restrictions
- Required status checks
- Force push restrictions
- Branch deletion restrictions
- Conversation resolution
- Signed commits required
- Linear history required

### Security Features (9 checks)
- Security policy (SECURITY.md)
- Dependabot alerts
- Dependabot config
- Code scanning (CodeQL)
- Secret scanning
- Push protection
- Critical/High vulnerability alerts
- Private vulnerability reporting

### Access Control (8 checks)
- Public repository warning
- Administrator count
- Outside collaborators
- Deploy keys with write access
- Old deploy keys
- Insecure webhook URLs
- Webhooks without secrets

### Repository Settings (14 checks)
- Wiki on public repo
- Issues disabled
- README, LICENSE, CODEOWNERS files
- GitHub Actions permissions
- GITHUB_TOKEN permissions
- Actions can approve PRs
- Private repo forking
- Unprotected environments

## Requirements

- GitHub Personal Access Token with appropriate scopes:
  - `repo` - Full control of private repositories
  - `read:org` - Read org membership
  - `security_events` - Read security events

## Getting Started

1. Open Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`)
2. Run `GitHub Security: Connect to GitHub`
3. Enter your GitHub Personal Access Token
4. Run `GitHub Security: Scan Repositories`
5. Select repositories to scan
6. View results in the GitHub Security panel

## Security Score

| Severity | Point Deduction |
|----------|-----------------|
| Critical | -25 points |
| High | -15 points |
| Medium | -8 points |
| Low | -3 points |
| Info | 0 points |

## Links

- [GitHub Repository](https://github.com/vdanniel/github-security-checker)
- [Report Issues](https://github.com/vdanniel/github-security-checker/issues)

## License

MIT
