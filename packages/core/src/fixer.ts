import { Octokit } from '@octokit/rest';

export interface FixResult {
  success: boolean;
  findingId: string;
  message: string;
  error?: string;
}

export class SecurityFixer {
  private octokit: Octokit;

  constructor(token: string) {
    this.octokit = new Octokit({ auth: token });
  }

  async fixFinding(owner: string, repo: string, findingId: string, branch?: string): Promise<FixResult> {
    try {
      switch (findingId) {
        case 'bp-not-enabled':
          return await this.enableBranchProtection(owner, repo, branch || 'main');
        case 'bp-no-pr-reviews':
          return await this.enablePRReviews(owner, repo, branch || 'main');
        case 'bp-admin-bypass':
          return await this.enforceAdmins(owner, repo, branch || 'main');
        case 'bp-stale-reviews':
          return await this.enableDismissStaleReviews(owner, repo, branch || 'main');
        case 'bp-low-review-count':
          return await this.setMinReviewers(owner, repo, branch || 'main', 2);
        case 'sf-no-dependabot-alerts':
          return await this.enableDependabotAlerts(owner, repo);
        case 'rs-token-write-permissions':
          return await this.setTokenReadPermissions(owner, repo);
        case 'rs-token-can-approve-prs':
          return await this.disableActionsApproval(owner, repo);
        case 'rs-no-auto-delete-branches':
          return await this.enableAutoDeleteBranches(owner, repo);
        case 'rs-private-forking-allowed':
          return await this.disableForking(owner, repo);
        default:
          return {
            success: false,
            findingId,
            message: 'No automatic fix available for this finding',
            error: 'UNSUPPORTED_FIX',
          };
      }
    } catch (error: any) {
      return { success: false, findingId, message: `Failed: ${error.message}`, error: error.message };
    }
  }

  private async enableBranchProtection(owner: string, repo: string, branch: string): Promise<FixResult> {
    await this.octokit.repos.updateBranchProtection({
      owner, repo, branch,
      required_status_checks: null,
      enforce_admins: true,
      required_pull_request_reviews: { dismiss_stale_reviews: true, required_approving_review_count: 1 },
      restrictions: null,
    });
    return { success: true, findingId: 'bp-not-enabled', message: 'Branch protection enabled' };
  }

  private async enablePRReviews(owner: string, repo: string, branch: string): Promise<FixResult> {
    await this.octokit.repos.updateBranchProtection({
      owner, repo, branch,
      required_status_checks: null,
      enforce_admins: null,
      required_pull_request_reviews: { dismiss_stale_reviews: true, required_approving_review_count: 1 },
      restrictions: null,
    });
    return { success: true, findingId: 'bp-no-pr-reviews', message: 'PR reviews now required' };
  }

  private async enforceAdmins(owner: string, repo: string, branch: string): Promise<FixResult> {
    await this.octokit.repos.setAdminBranchProtection({ owner, repo, branch });
    return { success: true, findingId: 'bp-admin-bypass', message: 'Admin enforcement enabled' };
  }

  private async enableDismissStaleReviews(owner: string, repo: string, branch: string): Promise<FixResult> {
    await this.octokit.repos.updateBranchProtection({
      owner, repo, branch,
      required_status_checks: null,
      enforce_admins: null,
      required_pull_request_reviews: { dismiss_stale_reviews: true, required_approving_review_count: 1 },
      restrictions: null,
    });
    return { success: true, findingId: 'bp-stale-reviews', message: 'Stale review dismissal enabled' };
  }

  private async setMinReviewers(owner: string, repo: string, branch: string, count: number): Promise<FixResult> {
    await this.octokit.repos.updateBranchProtection({
      owner, repo, branch,
      required_status_checks: null,
      enforce_admins: null,
      required_pull_request_reviews: { dismiss_stale_reviews: true, required_approving_review_count: count },
      restrictions: null,
    });
    return { success: true, findingId: 'bp-low-review-count', message: `Required reviewers set to ${count}` };
  }

  private async enableDependabotAlerts(owner: string, repo: string): Promise<FixResult> {
    await this.octokit.repos.enableVulnerabilityAlerts({ owner, repo });
    return { success: true, findingId: 'sf-no-dependabot-alerts', message: 'Dependabot alerts enabled' };
  }

  private async setTokenReadPermissions(owner: string, repo: string): Promise<FixResult> {
    await this.octokit.actions.setGithubActionsDefaultWorkflowPermissionsRepository({
      owner, repo, default_workflow_permissions: 'read',
    });
    return { success: true, findingId: 'rs-token-write-permissions', message: 'GITHUB_TOKEN set to read-only' };
  }

  private async disableActionsApproval(owner: string, repo: string): Promise<FixResult> {
    await this.octokit.actions.setGithubActionsDefaultWorkflowPermissionsRepository({
      owner, repo, can_approve_pull_request_reviews: false,
    });
    return { success: true, findingId: 'rs-token-can-approve-prs', message: 'Actions PR approval disabled' };
  }

  private async enableAutoDeleteBranches(owner: string, repo: string): Promise<FixResult> {
    await this.octokit.repos.update({ owner, repo, delete_branch_on_merge: true });
    return { success: true, findingId: 'rs-no-auto-delete-branches', message: 'Auto-delete branches enabled' };
  }

  private async disableForking(owner: string, repo: string): Promise<FixResult> {
    await this.octokit.repos.update({ owner, repo, allow_forking: false });
    return { success: true, findingId: 'rs-private-forking-allowed', message: 'Forking disabled' };
  }
}
