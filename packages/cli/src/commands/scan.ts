import { Command } from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import ora from 'ora';
import { GitHubSecurityScanner, RepoScanResult, Severity } from '@ghsec/core';
import { formatScanResults } from '../utils/formatter';

export const scanCommand = new Command('scan')
  .description('Scan GitHub repositories for security configuration issues')
  .option('-t, --token <token>', 'GitHub personal access token (or set GITHUB_TOKEN env)')
  .option('-r, --repos <repos...>', 'Specific repositories to scan (owner/repo format)')
  .option('-o, --org <org>', 'Scan all repositories in an organization')
  .option('--include-archived', 'Include archived repositories')
  .option('--include-forks', 'Include forked repositories')
  .option('-s, --severity <level>', 'Minimum severity to report', 'low')
  .option('--json', 'Output results as JSON')
  .option('--output <file>', 'Write results to file')
  .action(async (options) => {
    const token = options.token || process.env.GITHUB_TOKEN;
    if (!token) { console.error(chalk.red('Error: GitHub token required.')); process.exit(1); }

    const scanner = new GitHubSecurityScanner({ token, repos: options.repos, org: options.org, includeArchived: options.includeArchived, includeForks: options.includeForks, severityThreshold: options.severity as Severity });
    let reposToScan: string[] = options.repos || [];

    if (reposToScan.length === 0) {
      const spinner = ora('Fetching available repositories...').start();
      try {
        const availableRepos = await scanner.listAvailableRepos();
        spinner.stop();
        if (availableRepos.length === 0) { console.log(chalk.yellow('No repositories found.')); process.exit(0); }
        const { selectedRepos } = await inquirer.prompt([{ type: 'checkbox', name: 'selectedRepos', message: 'Select repositories to scan:', choices: availableRepos.map(r => ({ name: r.fullName, value: r.fullName })), pageSize: 20, validate: (answer) => answer.length === 0 ? 'Please select at least one repository.' : true }]);
        reposToScan = selectedRepos;
      } catch (error) { spinner.stop(); console.error(chalk.red('Error fetching repositories:'), error); process.exit(1); }
    }

    const results: RepoScanResult[] = [];
    for (const repoFullName of reposToScan) {
      const spinner = ora(`Scanning ${repoFullName}...`).start();
      try {
        const [owner, repo] = repoFullName.split('/');
        const result = await scanner.scanRepository(owner, repo);
        results.push(result);
        const issueCount = result.findings.length;
        if (issueCount === 0) spinner.succeed(`${repoFullName} - ${chalk.green('No issues found')} (Score: ${result.score}/100)`);
        else spinner.warn(`${repoFullName} - ${chalk.yellow(`${issueCount} issue(s)`)} (Score: ${result.score}/100)`);
      } catch (error: any) { spinner.fail(`${repoFullName} - ${chalk.red('Error:')} ${error.message}`); }
    }

    if (options.json) {
      const output = JSON.stringify(results, null, 2);
      if (options.output) { const fs = await import('fs'); fs.writeFileSync(options.output, output); console.log(chalk.green(`Results written to ${options.output}`)); }
      else console.log(output);
    } else {
      console.log('\n' + formatScanResults(results));
      if (options.output) { const fs = await import('fs'); fs.writeFileSync(options.output, formatScanResults(results)); console.log(chalk.green(`Results written to ${options.output}`)); }
    }
  });
