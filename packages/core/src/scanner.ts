import { Octokit } from '@octokit/rest';
import { ScannerConfig, RepoScanResult, SecurityFinding, Severity } from './types';
import { checkBranchProtection } from './checks/branch-protection';
import { checkSecurityFeatures, checkDependencyAlerts } from './checks/security-features';
import { checkAccessControl } from './checks/access-control';
import { checkRepositorySettings } from './checks/repository-settings';

export class GitHubSecurityScanner {
  private octokit: Octokit;
  private config: ScannerConfig;

  constructor(config: ScannerConfig) {
    this.config = config;
    this.octokit = new Octokit({ auth: config.token });
  }

  async listAvailableRepos(): Promise<Array<{ owner: string; name: string; fullName: string }>> {
    const repos: Array<{ owner: string; name: string; fullName: string }> = [];

    if (this.config.org) {
      const iterator = this.octokit.paginate.iterator(
        this.octokit.repos.listForOrg,
        { org: this.config.org, per_page: 100 }
      );
      for await (const { data } of iterator) {
        for (const repo of data) {
          if (!this.config.includeArchived && repo.archived) continue;
          if (!this.config.includeForks && repo.fork) continue;
          repos.push({ owner: repo.owner.login, name: repo.name, fullName: repo.full_name });
        }
      }
    } else {
      const iterator = this.octokit.paginate.iterator(
        this.octokit.repos.listForAuthenticatedUser,
        { per_page: 100 }
      );
      for await (const { data } of iterator) {
        for (const repo of data) {
          if (!this.config.includeArchived && repo.archived) continue;
          if (!this.config.includeForks && repo.fork) continue;
          repos.push({ owner: repo.owner.login, name: repo.name, fullName: repo.full_name });
        }
      }
    }
    return repos;
  }

  async scanRepository(owner: string, repo: string): Promise<RepoScanResult> {
    const { data: repoData } = await this.octokit.repos.get({ owner, repo });
    const allFindings: SecurityFinding[] = [];

    const [branchProtectionFindings, securityFeatureFindings, dependencyFindings, accessControlFindings, repoSettingsFindings] = await Promise.all([
      checkBranchProtection(this.octokit, owner, repo, repoData.default_branch),
      checkSecurityFeatures(this.octokit, owner, repo),
      checkDependencyAlerts(this.octokit, owner, repo),
      checkAccessControl(this.octokit, owner, repo),
      checkRepositorySettings(this.octokit, owner, repo),
    ]);

    allFindings.push(...branchProtectionFindings, ...securityFeatureFindings, ...dependencyFindings, ...accessControlFindings, ...repoSettingsFindings);

    const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const thresholdIndex = severityOrder.indexOf(this.config.severityThreshold || 'low');
    const filteredFindings = allFindings.filter(f => severityOrder.indexOf(f.severity) <= thresholdIndex);

    const summary = {
      critical: filteredFindings.filter(f => f.severity === 'critical').length,
      high: filteredFindings.filter(f => f.severity === 'high').length,
      medium: filteredFindings.filter(f => f.severity === 'medium').length,
      low: filteredFindings.filter(f => f.severity === 'low').length,
      info: filteredFindings.filter(f => f.severity === 'info').length,
      passed: 0,
    };

    return {
      repository: {
        owner,
        name: repo,
        fullName: repoData.full_name,
        visibility: repoData.visibility as 'public' | 'private' | 'internal',
        defaultBranch: repoData.default_branch,
        url: repoData.html_url,
      },
      scannedAt: new Date(),
      findings: filteredFindings,
      score: this.calculateScore(filteredFindings),
      summary,
    };
  }

  async scanMultipleRepos(repos: string[]): Promise<RepoScanResult[]> {
    const results: RepoScanResult[] = [];
    for (const repoFullName of repos) {
      const [owner, repo] = repoFullName.split('/');
      try {
        const result = await this.scanRepository(owner, repo);
        results.push(result);
      } catch (error) {
        console.error(`Error scanning ${repoFullName}:`, error);
      }
    }
    return results;
  }

  private calculateScore(findings: SecurityFinding[]): number {
    let score = 100;
    const deductions: Record<Severity, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
    for (const finding of findings) { score -= deductions[finding.severity]; }
    return Math.max(0, score);
  }
}

export { ScannerConfig, RepoScanResult, SecurityFinding };
