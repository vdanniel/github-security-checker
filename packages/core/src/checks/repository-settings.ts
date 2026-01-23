import { Octokit } from '@octokit/rest';
import { SecurityFinding } from '../types';

export async function checkRepositorySettings(octokit: Octokit, owner: string, repo: string): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  try {
    const { data: repoData } = await octokit.repos.get({ owner, repo });

    if (repoData.has_wiki && repoData.visibility === 'public') {
      findings.push({ id: 'rs-wiki-enabled', category: 'repository-settings', severity: 'info', title: 'Wiki enabled on public repository', description: 'Wiki is enabled and publicly accessible.', recommendation: 'Review wiki content for sensitive information or disable if not needed.', soc2Control: 'CC6.1' });
    }

    if (!repoData.has_issues) {
      findings.push({ id: 'rs-issues-disabled', category: 'repository-settings', severity: 'low', title: 'Issues disabled', description: 'GitHub Issues are disabled, which may limit security vulnerability reporting.', recommendation: 'Consider enabling Issues or ensure SECURITY.md has alternative reporting instructions.', soc2Control: 'CC7.4' });
    }

    if (repoData.default_branch === 'master') {
      findings.push({ id: 'rs-legacy-branch-name', category: 'repository-settings', severity: 'info', title: 'Legacy default branch name', description: 'Repository uses "master" as default branch. Consider renaming to "main".', recommendation: 'Rename default branch to "main" for consistency with GitHub standards.' });
    }

    try { await octokit.repos.getReadme({ owner, repo }); } catch {
      findings.push({ id: 'rs-no-readme', category: 'repository-settings', severity: 'low', title: 'No README file', description: 'Repository lacks a README file.', recommendation: 'Add a README.md with project documentation.' });
    }

    try { await octokit.licenses.getForRepo({ owner, repo }); } catch {
      findings.push({ id: 'rs-no-license', category: 'repository-settings', severity: 'low', title: 'No license file', description: 'Repository lacks a LICENSE file.', recommendation: 'Add a LICENSE file to clarify usage terms.' });
    }

    const codeownersPaths = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'];
    let hasCodeowners = false;
    for (const path of codeownersPaths) {
      try { await octokit.repos.getContent({ owner, repo, path }); hasCodeowners = true; break; } catch { /* continue */ }
    }
    if (!hasCodeowners) {
      findings.push({ id: 'rs-no-codeowners', category: 'repository-settings', severity: 'medium', title: 'No CODEOWNERS file', description: 'Repository lacks a CODEOWNERS file for automatic review assignment.', recommendation: 'Create a CODEOWNERS file to ensure proper code review coverage.', soc2Control: 'CC6.1' });
    }

    try {
      const { data: actionsPermissions } = await octokit.actions.getGithubActionsPermissionsRepository({ owner, repo });
      if (actionsPermissions.enabled && actionsPermissions.allowed_actions === 'all') {
        findings.push({ id: 'rs-actions-all-allowed', category: 'repository-settings', severity: 'medium', title: 'All GitHub Actions allowed', description: 'Repository allows all GitHub Actions without restrictions.', recommendation: 'Restrict Actions to verified creators or specific allowed actions.', soc2Control: 'CC6.1' });
      }
    } catch { /* Actions might not be enabled */ }

    try { await octokit.repos.getContent({ owner, repo, path: '.gitignore' }); } catch {
      findings.push({ id: 'rs-no-gitignore', category: 'repository-settings', severity: 'low', title: 'No .gitignore file', description: 'Repository lacks a .gitignore file, risking accidental commits of sensitive files.', recommendation: 'Add a .gitignore file appropriate for your project type.', soc2Control: 'CC6.7' });
    }

  } catch (error) {
    console.error('Error checking repository settings:', error);
    throw error;
  }

  return findings;
}
