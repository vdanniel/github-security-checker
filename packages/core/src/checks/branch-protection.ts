import { Octokit } from '@octokit/rest';
import { SecurityFinding } from '../types';

export async function checkBranchProtection(
  octokit: Octokit,
  owner: string,
  repo: string,
  branch: string
): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  try {
    const { data } = await octokit.repos.getBranchProtection({
      owner,
      repo,
      branch,
    });

    // Check required PR reviews
    if (!data.required_pull_request_reviews) {
      findings.push({
        id: 'bp-no-pr-reviews',
        category: 'branch-protection',
        severity: 'high',
        title: 'Pull request reviews not required',
        description: `The ${branch} branch does not require pull request reviews before merging.`,
        recommendation: 'Enable "Require pull request reviews before merging" in branch protection settings.',
        documentationUrl: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-pull-request-reviews-before-merging',
        soc2Control: 'CC6.1',
      });
    } else {
      const reviews = data.required_pull_request_reviews;

      if (!reviews.dismiss_stale_reviews) {
        findings.push({
          id: 'bp-stale-reviews',
          category: 'branch-protection',
          severity: 'medium',
          title: 'Stale reviews not dismissed',
          description: 'Approved reviews are not dismissed when new commits are pushed.',
          recommendation: 'Enable "Dismiss stale pull request approvals when new commits are pushed".',
          documentationUrl: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#dismiss-stale-pull-request-approvals-when-new-commits-are-pushed',
          soc2Control: 'CC6.1',
        });
      }

      if (!reviews.require_code_owner_reviews) {
        findings.push({
          id: 'bp-no-codeowner-review',
          category: 'branch-protection',
          severity: 'medium',
          title: 'Code owner reviews not required',
          description: 'Reviews from code owners are not required for changes to owned files.',
          recommendation: 'Enable "Require review from Code Owners" and create a CODEOWNERS file.',
          documentationUrl: 'https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners',
          soc2Control: 'CC6.1',
        });
      }

      if ((reviews.required_approving_review_count || 0) < 2) {
        findings.push({
          id: 'bp-low-review-count',
          category: 'branch-protection',
          severity: 'medium',
          title: 'Insufficient required reviewers',
          description: `Only ${reviews.required_approving_review_count || 0} reviewer(s) required. Best practice is at least 2.`,
          recommendation: 'Increase required approving reviews to at least 2.',
          currentValue: reviews.required_approving_review_count || 0,
          expectedValue: 2,
          soc2Control: 'CC6.1',
        });
      }
    }

    // Check enforce admins
    if (!data.enforce_admins?.enabled) {
      findings.push({
        id: 'bp-admin-bypass',
        category: 'branch-protection',
        severity: 'high',
        title: 'Administrators can bypass protection',
        description: 'Repository administrators can bypass branch protection rules.',
        recommendation: 'Enable "Do not allow bypassing the above settings" for administrators.',
        documentationUrl: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#do-not-allow-bypassing-the-above-settings',
        soc2Control: 'CC6.1',
      });
    }

    // Check required status checks
    if (!data.required_status_checks || data.required_status_checks.contexts.length === 0) {
      findings.push({
        id: 'bp-no-status-checks',
        category: 'branch-protection',
        severity: 'high',
        title: 'No required status checks',
        description: 'No CI/CD status checks are required before merging.',
        recommendation: 'Configure required status checks (e.g., CI tests, linting) before merging.',
        documentationUrl: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging',
        soc2Control: 'CC7.1',
      });
    }

    // Check force push
    if (data.allow_force_pushes?.enabled) {
      findings.push({
        id: 'bp-force-push-allowed',
        category: 'branch-protection',
        severity: 'high',
        title: 'Force pushes allowed',
        description: 'Force pushes are allowed, which can rewrite history and remove commits.',
        recommendation: 'Disable "Allow force pushes" to prevent history rewriting.',
        soc2Control: 'CC6.1',
      });
    }

    // Check deletions
    if (data.allow_deletions?.enabled) {
      findings.push({
        id: 'bp-deletions-allowed',
        category: 'branch-protection',
        severity: 'medium',
        title: 'Branch deletion allowed',
        description: 'The protected branch can be deleted.',
        recommendation: 'Disable "Allow deletions" to prevent accidental branch removal.',
        soc2Control: 'CC6.1',
      });
    }

    // Check conversation resolution
    if (!data.required_conversation_resolution?.enabled) {
      findings.push({
        id: 'bp-no-conversation-resolution',
        category: 'branch-protection',
        severity: 'low',
        title: 'Conversation resolution not required',
        description: 'PRs can be merged without resolving all review comments.',
        recommendation: 'Enable "Require conversation resolution before merging".',
        soc2Control: 'CC6.1',
      });
    }

    // Check required signatures (signed commits)
    if (!data.required_signatures?.enabled) {
      findings.push({
        id: 'bp-no-signed-commits',
        category: 'branch-protection',
        severity: 'medium',
        title: 'Signed commits not required',
        description: 'Commits are not required to be signed with GPG or SSH keys.',
        recommendation: 'Enable "Require signed commits" to verify commit authenticity.',
        documentationUrl: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-signed-commits',
        soc2Control: 'CC6.1',
      });
    }

    // Check linear history requirement
    if (!data.required_linear_history?.enabled) {
      findings.push({
        id: 'bp-no-linear-history',
        category: 'branch-protection',
        severity: 'low',
        title: 'Linear history not required',
        description: 'Merge commits are allowed, which can complicate history.',
        recommendation: 'Enable "Require linear history" to enforce squash or rebase merging.',
        documentationUrl: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-linear-history',
        soc2Control: 'CC6.1',
      });
    }

  } catch (error: any) {
    if (error.status === 404) {
      findings.push({
        id: 'bp-not-enabled',
        category: 'branch-protection',
        severity: 'critical',
        title: 'Branch protection not enabled',
        description: `The ${branch} branch has no protection rules configured.`,
        recommendation: 'Enable branch protection for the default branch immediately.',
        documentationUrl: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule',
        soc2Control: 'CC6.1',
      });
    } else if (error.status === 403) {
      // Branch protection not available for private repos without GitHub Pro
      findings.push({
        id: 'bp-not-available',
        category: 'branch-protection',
        severity: 'info',
        title: 'Branch protection not available',
        description: 'Branch protection requires GitHub Pro for private repositories.',
        recommendation: 'Upgrade to GitHub Pro or make the repository public to enable branch protection.',
        documentationUrl: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches',
        soc2Control: 'CC6.1',
      });
    } else {
      throw error;
    }
  }

  return findings;
}
