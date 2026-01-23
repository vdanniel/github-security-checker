#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  GitHubSecurityScanner,
  generateSOC2Report,
  formatSOC2ReportMarkdown,
  Severity,
} from '@ghsec/core';

const server = new Server(
  {
    name: 'github-security-checker',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Tool definitions
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'list_repos',
        description: 'List available GitHub repositories that can be scanned',
        inputSchema: {
          type: 'object',
          properties: {
            token: {
              type: 'string',
              description: 'GitHub personal access token (optional if GITHUB_TOKEN env is set)',
            },
            org: {
              type: 'string',
              description: 'Organization name to list repos from (optional)',
            },
            includeArchived: {
              type: 'boolean',
              description: 'Include archived repositories',
              default: false,
            },
            includeForks: {
              type: 'boolean',
              description: 'Include forked repositories',
              default: false,
            },
          },
        },
      },
      {
        name: 'scan_repo',
        description: 'Scan a GitHub repository for security configuration issues and best practices',
        inputSchema: {
          type: 'object',
          properties: {
            token: {
              type: 'string',
              description: 'GitHub personal access token (optional if GITHUB_TOKEN env is set)',
            },
            repo: {
              type: 'string',
              description: 'Repository to scan in owner/repo format (e.g., "octocat/hello-world")',
            },
            severity: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low', 'info'],
              description: 'Minimum severity level to report',
              default: 'low',
            },
          },
          required: ['repo'],
        },
      },
      {
        name: 'scan_multiple_repos',
        description: 'Scan multiple GitHub repositories for security issues',
        inputSchema: {
          type: 'object',
          properties: {
            token: {
              type: 'string',
              description: 'GitHub personal access token (optional if GITHUB_TOKEN env is set)',
            },
            repos: {
              type: 'array',
              items: { type: 'string' },
              description: 'List of repositories to scan in owner/repo format',
            },
            severity: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low', 'info'],
              description: 'Minimum severity level to report',
              default: 'low',
            },
          },
          required: ['repos'],
        },
      },
      {
        name: 'generate_soc2_report',
        description: 'Generate a SOC 2 compliance report for selected repositories',
        inputSchema: {
          type: 'object',
          properties: {
            token: {
              type: 'string',
              description: 'GitHub personal access token (optional if GITHUB_TOKEN env is set)',
            },
            repos: {
              type: 'array',
              items: { type: 'string' },
              description: 'List of repositories to include in the report',
            },
          },
          required: ['repos'],
        },
      },
      {
        name: 'get_recommendations',
        description: 'Get specific recommendations for fixing a security finding',
        inputSchema: {
          type: 'object',
          properties: {
            findingId: {
              type: 'string',
              description: 'The finding ID to get recommendations for',
            },
            repo: {
              type: 'string',
              description: 'Repository context in owner/repo format',
            },
          },
          required: ['findingId'],
        },
      },
    ],
  };
});

// Tool implementations
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const token = (args?.token as string) || process.env.GITHUB_TOKEN;

  if (!token) {
    return {
      content: [
        {
          type: 'text',
          text: 'Error: GitHub token required. Provide token parameter or set GITHUB_TOKEN environment variable.',
        },
      ],
    };
  }

  try {
    switch (name) {
      case 'list_repos': {
        const scanner = new GitHubSecurityScanner({
          token,
          org: args?.org as string,
          includeArchived: args?.includeArchived as boolean,
          includeForks: args?.includeForks as boolean,
        });

        const repos = await scanner.listAvailableRepos();
        return {
          content: [
            {
              type: 'text',
              text: `Found ${repos.length} repositories:\n\n${repos.map(r => `- ${r.fullName}`).join('\n')}`,
            },
          ],
        };
      }

      case 'scan_repo': {
        const scanner = new GitHubSecurityScanner({
          token,
          severityThreshold: (args?.severity as Severity) || 'low',
        });

        const [owner, repo] = (args?.repo as string).split('/');
        const result = await scanner.scanRepository(owner, repo);

        let response = `## Security Scan: ${result.repository.fullName}\n\n`;
        response += `**Score:** ${result.score}/100\n`;
        response += `**Visibility:** ${result.repository.visibility}\n`;
        response += `**Default Branch:** ${result.repository.defaultBranch}\n\n`;

        if (result.findings.length === 0) {
          response += '✅ **No security issues found!**\n';
        } else {
          response += `### Findings (${result.findings.length})\n\n`;
          
          for (const finding of result.findings) {
            const icon = finding.severity === 'critical' ? '🔴' :
                        finding.severity === 'high' ? '🟠' :
                        finding.severity === 'medium' ? '🟡' : '🔵';
            
            response += `${icon} **${finding.title}** (${finding.severity})\n`;
            response += `   ${finding.description}\n`;
            response += `   💡 *${finding.recommendation}*\n`;
            if (finding.documentationUrl) {
              response += `   📚 [Documentation](${finding.documentationUrl})\n`;
            }
            response += '\n';
          }
        }

        response += `\n### Summary\n`;
        response += `- Critical: ${result.summary.critical}\n`;
        response += `- High: ${result.summary.high}\n`;
        response += `- Medium: ${result.summary.medium}\n`;
        response += `- Low: ${result.summary.low}\n`;

        return {
          content: [{ type: 'text', text: response }],
        };
      }

      case 'scan_multiple_repos': {
        const scanner = new GitHubSecurityScanner({
          token,
          severityThreshold: (args?.severity as Severity) || 'low',
        });

        const repos = args?.repos as string[];
        const results = await scanner.scanMultipleRepos(repos);

        let response = `## Security Scan Results\n\n`;
        response += `Scanned ${results.length} repositories\n\n`;

        for (const result of results) {
          const icon = result.score >= 80 ? '✅' : result.score >= 60 ? '⚠️' : '❌';
          response += `${icon} **${result.repository.fullName}** - Score: ${result.score}/100, Issues: ${result.findings.length}\n`;
        }

        const avgScore = Math.round(results.reduce((sum, r) => sum + r.score, 0) / results.length);
        response += `\n**Average Score:** ${avgScore}/100\n`;

        return {
          content: [{ type: 'text', text: response }],
        };
      }

      case 'generate_soc2_report': {
        const scanner = new GitHubSecurityScanner({
          token,
          severityThreshold: 'info',
        });

        const repos = args?.repos as string[];
        const results = await scanner.scanMultipleRepos(repos);
        const report = generateSOC2Report(results);
        const markdown = formatSOC2ReportMarkdown(report);

        return {
          content: [{ type: 'text', text: markdown }],
        };
      }

      case 'get_recommendations': {
        const recommendations = getDetailedRecommendations(args?.findingId as string);
        return {
          content: [{ type: 'text', text: recommendations }],
        };
      }

      default:
        return {
          content: [{ type: 'text', text: `Unknown tool: ${name}` }],
        };
    }
  } catch (error: any) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${error.message}`,
        },
      ],
    };
  }
});

function getDetailedRecommendations(findingId: string): string {
  const recommendations: Record<string, string> = {
    'bp-not-enabled': `## Enable Branch Protection\n\n### Steps:\n1. Go to your repository on GitHub\n2. Click **Settings** → **Branches**\n3. Under "Branch protection rules", click **Add rule**\n4. Enter your default branch name (e.g., \`main\`)\n5. Configure the following recommended settings:\n   - ✅ Require a pull request before merging\n   - ✅ Require approvals (at least 2)\n   - ✅ Dismiss stale pull request approvals\n   - ✅ Require status checks to pass\n   - ✅ Do not allow bypassing the above settings\n\n### API Alternative:\n\`\`\`bash\ngh api repos/{owner}/{repo}/branches/main/protection -X PUT -f required_status_checks='{"strict":true,"contexts":[]}' -f enforce_admins=true -f required_pull_request_reviews='{"required_approving_review_count":2}'\n\`\`\`\n`,
    'bp-no-pr-reviews': `## Enable Required Pull Request Reviews\n\n### Steps:\n1. Go to **Settings** → **Branches** → Edit your branch protection rule\n2. Check **Require a pull request before merging**\n3. Set **Required approvals** to at least 2\n4. Enable **Dismiss stale pull request approvals when new commits are pushed**\n5. Enable **Require review from Code Owners**\n`,
    'sf-no-dependabot-alerts': `## Enable Dependabot Alerts\n\n### Steps:\n1. Go to **Settings** → **Code security and analysis**\n2. Enable **Dependency graph**\n3. Enable **Dependabot alerts**\n4. Optionally enable **Dependabot security updates**\n\n### Benefits:\n- Automatic vulnerability detection in dependencies\n- Security advisories for known CVEs\n- Automated pull requests for security fixes\n`,
    'sf-no-code-scanning': `## Enable Code Scanning with CodeQL\n\n### Steps:\n1. Go to **Security** → **Code scanning alerts**\n2. Click **Set up code scanning**\n3. Select **CodeQL Analysis** → **Set up this workflow**\n4. Commit the workflow file to your repository\n\n### Manual Workflow:\nCreate \`.github/workflows/codeql.yml\`:\n\`\`\`yaml\nname: "CodeQL"\non:\n  push:\n    branches: [ main ]\n  pull_request:\n    branches: [ main ]\n  schedule:\n    - cron: '0 0 * * 0'\n\njobs:\n  analyze:\n    runs-on: ubuntu-latest\n    permissions:\n      security-events: write\n    steps:\n      - uses: actions/checkout@v4\n      - uses: github/codeql-action/init@v3\n      - uses: github/codeql-action/autobuild@v3\n      - uses: github/codeql-action/analyze@v3\n\`\`\`\n`,
    'sf-no-security-policy': `## Add Security Policy\n\n### Steps:\n1. Create a file named \`SECURITY.md\` in your repository root or \`.github\` folder\n2. Include:\n   - Supported versions\n   - How to report vulnerabilities\n   - Expected response time\n   - Disclosure policy\n\n### Template:\n\`\`\`markdown\n# Security Policy\n\n## Supported Versions\n| Version | Supported |\n| ------- | --------- |\n| 1.x.x   | ✅        |\n| < 1.0   | ❌        |\n\n## Reporting a Vulnerability\nPlease report security vulnerabilities to security@example.com.\nWe will respond within 48 hours and provide updates every 72 hours.\n\`\`\`\n`,
  };

  return recommendations[findingId] || `No detailed recommendations available for finding: ${findingId}. Please refer to the general recommendation in the scan results.`;
}

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('GitHub Security Checker MCP server running');
}

main().catch(console.error);
