import { Octokit } from '@octokit/rest';
import { SecurityFinding } from '../types';

export async function checkRepositorySettings(
  octokit: Octokit,
  owner: string,
  repo: string
): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  try {
    const { data: repoData } = await octokit.repos.get({ owner, repo });

    // Check if wiki is enabled (potential data leak vector)
    if (repoData.has_wiki && repoData.visibility === 'public') {
      findings.push({
        id: 'rs-wiki-enabled',
        category: 'repository-settings',
        severity: 'info',
        title: 'Wiki enabled on public repository',
        description: 'Wiki is enabled and publicly accessible.',
        recommendation: 'Review wiki content for sensitive information or disable if not needed.',
        soc2Control: 'CC6.1',
      });
    }

    // Check if issues are enabled (for security reporting)
    if (!repoData.has_issues) {
      findings.push({
        id: 'rs-issues-disabled',
        category: 'repository-settings',
        severity: 'low',
        title: 'Issues disabled',
        description: 'GitHub Issues are disabled, which may limit security vulnerability reporting.',
        recommendation: 'Consider enabling Issues or ensure SECURITY.md has alternative reporting instructions.',
        soc2Control: 'CC7.4',
      });
    }

    // Check default branch name (main vs master - informational)
    if (repoData.default_branch === 'master') {
      findings.push({
        id: 'rs-legacy-branch-name',
        category: 'repository-settings',
        severity: 'info',
        title: 'Legacy default branch name',
        description: 'Repository uses "master" as default branch. Consider renaming to "main".',
        recommendation: 'Rename default branch to "main" for consistency with GitHub standards.',
        documentationUrl: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-branches-in-your-repository/renaming-a-branch',
      });
    }

    // Check for README
    try {
      await octokit.repos.getReadme({ owner, repo });
    } catch {
      findings.push({
        id: 'rs-no-readme',
        category: 'repository-settings',
        severity: 'low',
        title: 'No README file',
        description: 'Repository lacks a README file.',
        recommendation: 'Add a README.md with project documentation.',
      });
    }

    // Check for LICENSE
    try {
      await octokit.licenses.getForRepo({ owner, repo });
    } catch {
      findings.push({
        id: 'rs-no-license',
        category: 'repository-settings',
        severity: 'low',
        title: 'No license file',
        description: 'Repository lacks a LICENSE file.',
        recommendation: 'Add a LICENSE file to clarify usage terms.',
        documentationUrl: 'https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository',
      });
    }

    // Check for CODEOWNERS
    const codeownersPaths = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'];
    let hasCodeowners = false;
    
    for (const path of codeownersPaths) {
      try {
        await octokit.repos.getContent({ owner, repo, path });
        hasCodeowners = true;
        break;
      } catch {
        // Continue checking other paths
      }
    }

    if (!hasCodeowners) {
      findings.push({
        id: 'rs-no-codeowners',
        category: 'repository-settings',
        severity: 'medium',
        title: 'No CODEOWNERS file',
        description: 'Repository lacks a CODEOWNERS file for automatic review assignment.',
        recommendation: 'Create a CODEOWNERS file to ensure proper code review coverage.',
        documentationUrl: 'https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners',
        soc2Control: 'CC6.1',
      });
    }

    // Check Actions permissions
    try {
      const { data: actionsPermissions } = await octokit.actions.getGithubActionsPermissionsRepository({
        owner,
        repo,
      });

      if (actionsPermissions.enabled && actionsPermissions.allowed_actions === 'all') {
        findings.push({
          id: 'rs-actions-all-allowed',
          category: 'repository-settings',
          severity: 'medium',
          title: 'All GitHub Actions allowed',
          description: 'Repository allows all GitHub Actions without restrictions.',
          recommendation: 'Restrict Actions to verified creators or specific allowed actions.',
          documentationUrl: 'https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository',
          soc2Control: 'CC6.1',
        });
      }
    } catch {
      // Actions might not be enabled or accessible
    }

    // Check for .gitignore
    try {
      await octokit.repos.getContent({ owner, repo, path: '.gitignore' });
    } catch {
      findings.push({
        id: 'rs-no-gitignore',
        category: 'repository-settings',
        severity: 'low',
        title: 'No .gitignore file',
        description: 'Repository lacks a .gitignore file, risking accidental commits of sensitive files.',
        recommendation: 'Add a .gitignore file appropriate for your project type.',
        documentationUrl: 'https://docs.github.com/en/get-started/getting-started-with-git/ignoring-files',
        soc2Control: 'CC6.7',
      });
    }

    // Check default GITHUB_TOKEN permissions
    try {
      const { data: workflowSettings } = await octokit.actions.getGithubActionsDefaultWorkflowPermissionsRepository({
        owner,
        repo,
      });

      if (workflowSettings.default_workflow_permissions === 'write') {
        findings.push({
          id: 'rs-token-write-permissions',
          category: 'repository-settings',
          severity: 'high',
          title: 'GITHUB_TOKEN has write permissions by default',
          description: 'Workflows have write permissions by default, increasing attack surface.',
          recommendation: 'Set default GITHUB_TOKEN permissions to "read" and grant write permissions explicitly per workflow.',
          documentationUrl: 'https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token',
          soc2Control: 'CC6.1',
        });
      }

      if (workflowSettings.can_approve_pull_request_reviews) {
        findings.push({
          id: 'rs-token-can-approve-prs',
          category: 'repository-settings',
          severity: 'medium',
          title: 'Actions can approve pull requests',
          description: 'GitHub Actions workflows can approve pull requests, which could bypass review requirements.',
          recommendation: 'Disable "Allow GitHub Actions to create and approve pull requests" unless required.',
          documentationUrl: 'https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository',
          soc2Control: 'CC6.1',
        });
      }
    } catch {
      // May not have permission to check workflow settings
    }

    // Check fork settings for private repos
    if (repoData.visibility === 'private') {
      if (repoData.allow_forking) {
        findings.push({
          id: 'rs-private-forking-allowed',
          category: 'repository-settings',
          severity: 'medium',
          title: 'Forking allowed for private repository',
          description: 'Private repository allows forking, which could lead to code duplication outside org control.',
          recommendation: 'Disable forking for private repositories unless explicitly needed.',
          documentationUrl: 'https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/managing-the-forking-policy-for-your-repository',
          soc2Control: 'CC6.1',
        });
      }
    }

    // Check merge commit settings
    const mergeSettings = {
      allowMergeCommit: repoData.allow_merge_commit,
      allowSquashMerge: repoData.allow_squash_merge,
      allowRebaseMerge: repoData.allow_rebase_merge,
    };

    // If all merge types are allowed, recommend restricting
    if (mergeSettings.allowMergeCommit && mergeSettings.allowSquashMerge && mergeSettings.allowRebaseMerge) {
      findings.push({
        id: 'rs-all-merge-types-allowed',
        category: 'repository-settings',
        severity: 'info',
        title: 'All merge strategies allowed',
        description: 'Repository allows merge commits, squash merging, and rebase merging.',
        recommendation: 'Consider restricting to squash or rebase merging for cleaner history.',
        documentationUrl: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/about-merge-methods-on-github',
      });
    }

    // Check if delete branch on merge is enabled
    if (!repoData.delete_branch_on_merge) {
      findings.push({
        id: 'rs-no-auto-delete-branches',
        category: 'repository-settings',
        severity: 'low',
        title: 'Auto-delete branches disabled',
        description: 'Merged branches are not automatically deleted.',
        recommendation: 'Enable "Automatically delete head branches" to keep repository clean.',
        documentationUrl: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-the-automatic-deletion-of-branches',
      });
    }

    // Check for environments (deployment protection)
    try {
      const { data: environments } = await octokit.repos.getAllEnvironments({
        owner,
        repo,
      });

      if (environments.environments && environments.environments.length > 0) {
        const unprotectedEnvs = environments.environments.filter(
          env => !env.protection_rules || env.protection_rules.length === 0
        );

        if (unprotectedEnvs.length > 0) {
          findings.push({
            id: 'rs-unprotected-environments',
            category: 'repository-settings',
            severity: 'medium',
            title: 'Unprotected deployment environments',
            description: `${unprotectedEnvs.length} environment(s) have no protection rules configured.`,
            recommendation: 'Add protection rules (required reviewers, wait timers) to deployment environments.',
            documentationUrl: 'https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment',
            soc2Control: 'CC6.1',
            currentValue: unprotectedEnvs.map(e => e.name).join(', '),
          });
        }
      }
    } catch {
      // Environments might not be accessible
    }

  } catch (error) {
    console.error('Error checking repository settings:', error);
    throw error;
  }

  return findings;
}
