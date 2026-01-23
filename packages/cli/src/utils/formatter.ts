import chalk from 'chalk';
import { RepoScanResult, SecurityFinding, Severity } from '@ghsec/core';

const severityColors: Record<Severity, (text: string) => string> = { critical: chalk.bgRed.white, high: chalk.red, medium: chalk.yellow, low: chalk.blue, info: chalk.gray };
const severityIcons: Record<Severity, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ️' };

export function formatScanResults(results: RepoScanResult[]): string {
  const lines: string[] = [];
  lines.push(chalk.bold('\n═══════════════════════════════════════════════════════════════'));
  lines.push(chalk.bold('                    SECURITY SCAN RESULTS'));
  lines.push(chalk.bold('═══════════════════════════════════════════════════════════════\n'));
  for (const result of results) { lines.push(formatRepoResult(result)); lines.push(''); }
  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  const avgScore = Math.round(results.reduce((sum, r) => sum + r.score, 0) / results.length);
  lines.push(chalk.bold('───────────────────────────────────────────────────────────────'));
  lines.push(chalk.bold('SUMMARY'));
  lines.push(`Repositories scanned: ${results.length}`);
  lines.push(`Total findings: ${totalFindings}`);
  lines.push(`Average security score: ${formatScore(avgScore)}`);
  lines.push(chalk.bold('───────────────────────────────────────────────────────────────'));
  return lines.join('\n');
}

function formatRepoResult(result: RepoScanResult): string {
  const lines: string[] = [];
  lines.push(chalk.bold(`📁 ${result.repository.fullName}`));
  lines.push(`   ${chalk.dim(result.repository.url)}`);
  lines.push(`   Visibility: ${result.repository.visibility} | Branch: ${result.repository.defaultBranch}`);
  lines.push(`   Security Score: ${formatScore(result.score)}`);
  lines.push('');
  if (result.findings.length === 0) { lines.push(chalk.green('   ✅ No security issues found!')); }
  else {
    const byCategory = groupBy(result.findings, 'category');
    for (const [category, findings] of Object.entries(byCategory)) {
      lines.push(chalk.bold(`   ${formatCategory(category)}`));
      for (const finding of findings) lines.push(formatFinding(finding));
      lines.push('');
    }
  }
  const { summary } = result;
  const counts = [summary.critical > 0 ? chalk.bgRed.white(` ${summary.critical} CRITICAL `) : null, summary.high > 0 ? chalk.red(`${summary.high} high`) : null, summary.medium > 0 ? chalk.yellow(`${summary.medium} medium`) : null, summary.low > 0 ? chalk.blue(`${summary.low} low`) : null, summary.info > 0 ? chalk.gray(`${summary.info} info`) : null].filter(Boolean);
  if (counts.length > 0) lines.push(`   Findings: ${counts.join(' | ')}`);
  return lines.join('\n');
}

function formatFinding(finding: SecurityFinding): string {
  const icon = severityIcons[finding.severity];
  const colorFn = severityColors[finding.severity];
  const lines: string[] = [];
  lines.push(`      ${icon} ${colorFn(finding.severity.toUpperCase())} ${finding.title}`);
  lines.push(chalk.dim(`         ${finding.description}`));
  lines.push(chalk.cyan(`         💡 ${finding.recommendation}`));
  if (finding.documentationUrl) lines.push(chalk.dim(`         📚 ${finding.documentationUrl}`));
  return lines.join('\n');
}

function formatScore(score: number): string {
  if (score >= 80) return chalk.green(`${score}/100 ✓`);
  else if (score >= 60) return chalk.yellow(`${score}/100`);
  else return chalk.red(`${score}/100 ⚠`);
}

function formatCategory(category: string): string {
  const categoryNames: Record<string, string> = { 'branch-protection': '🔒 Branch Protection', 'security-features': '🛡️ Security Features', 'access-control': '👥 Access Control', 'repository-settings': '⚙️ Repository Settings', 'secrets': '🔑 Secrets', 'dependencies': '📦 Dependencies' };
  return categoryNames[category] || category;
}

function groupBy<T>(array: T[], key: keyof T): Record<string, T[]> {
  return array.reduce((result, item) => { const groupKey = String(item[key]); if (!result[groupKey]) result[groupKey] = []; result[groupKey].push(item); return result; }, {} as Record<string, T[]>);
}
