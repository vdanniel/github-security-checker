import { Command } from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import ora from 'ora';
import { GitHubSecurityScanner, generateSOC2Report, formatSOC2ReportMarkdown, formatSOC2ReportJSON, Severity } from '@ghsec/core';

export const reportCommand = new Command('report')
  .description('Generate compliance reports from security scans')
  .option('-t, --token <token>', 'GitHub personal access token (or set GITHUB_TOKEN env)')
  .option('-r, --repos <repos...>', 'Specific repositories to include (owner/repo format)')
  .option('-o, --org <org>', 'Include all repositories in an organization')
  .option('--type <type>', 'Report type (soc2)', 'soc2')
  .option('--format <format>', 'Output format (markdown|json)', 'markdown')
  .option('--output <file>', 'Write report to file')
  .action(async (options) => {
    const token = options.token || process.env.GITHUB_TOKEN;
    if (!token) { console.error(chalk.red('Error: GitHub token required.')); process.exit(1); }

    const scanner = new GitHubSecurityScanner({ token, repos: options.repos, org: options.org, severityThreshold: 'info' as Severity });
    let reposToScan: string[] = options.repos || [];

    if (reposToScan.length === 0) {
      const spinner = ora('Fetching available repositories...').start();
      try {
        const availableRepos = await scanner.listAvailableRepos();
        spinner.stop();
        if (availableRepos.length === 0) { console.log(chalk.yellow('No repositories found.')); process.exit(0); }
        const { selectedRepos } = await inquirer.prompt([{ type: 'checkbox', name: 'selectedRepos', message: 'Select repositories for compliance report:', choices: availableRepos.map(r => ({ name: r.fullName, value: r.fullName })), pageSize: 20, validate: (answer) => answer.length === 0 ? 'Please select at least one repository.' : true }]);
        reposToScan = selectedRepos;
      } catch (error) { spinner.stop(); console.error(chalk.red('Error fetching repositories:'), error); process.exit(1); }
    }

    const spinner = ora('Scanning repositories for compliance report...').start();
    const results = await scanner.scanMultipleRepos(reposToScan);
    spinner.succeed(`Scanned ${results.length} repositories`);

    if (options.type === 'soc2') {
      const report = generateSOC2Report(results);
      let output: string = options.format === 'json' ? formatSOC2ReportJSON(report) : formatSOC2ReportMarkdown(report);
      if (options.output) { const fs = await import('fs'); fs.writeFileSync(options.output, output); console.log(chalk.green(`\nSOC 2 report written to ${options.output}`)); console.log(`Overall Compliance: ${report.overallCompliance}%`); }
      else console.log('\n' + output);
    } else { console.error(chalk.red(`Unknown report type: ${options.type}`)); process.exit(1); }
  });
