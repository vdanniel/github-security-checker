import { Octokit } from '@octokit/rest';
import { SecurityFinding } from '../types';

export async function checkAccessControl(octokit: Octokit, owner: string, repo: string): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  try {
    const { data: repoData } = await octokit.repos.get({ owner, repo });

    if (repoData.visibility === 'public') {
      findings.push({ id: 'ac-public-repo', category: 'access-control', severity: 'info', title: 'Repository is public', description: 'This repository is publicly accessible. Ensure no sensitive data is exposed.', recommendation: 'Review repository contents for sensitive information. Consider making private if needed.', soc2Control: 'CC6.1' });
    }

    try {
      const { data: collaborators } = await octokit.repos.listCollaborators({ owner, repo, per_page: 100 });
      const admins = collaborators.filter((c: any) => c.permissions?.admin);
      if (admins.length > 5) {
        findings.push({ id: 'ac-too-many-admins', category: 'access-control', severity: 'medium', title: 'High number of administrators', description: `Repository has ${admins.length} users with admin access.`, recommendation: 'Review admin access and apply principle of least privilege.', soc2Control: 'CC6.1', currentValue: admins.length, expectedValue: '≤5' });
      }
      const outsideCollaborators = collaborators.filter((c: any) => c.permissions?.push && !c.permissions?.admin);
      if (outsideCollaborators.length > 0) {
        findings.push({ id: 'ac-outside-collaborators', category: 'access-control', severity: 'info', title: 'Outside collaborators with write access', description: `${outsideCollaborators.length} collaborator(s) have write access.`, recommendation: 'Periodically review outside collaborator access.', soc2Control: 'CC6.2', currentValue: outsideCollaborators.length });
      }
    } catch { /* May not have permission */ }

    try {
      const { data: deployKeys } = await octokit.repos.listDeployKeys({ owner, repo, per_page: 100 });
      const writeKeys = deployKeys.filter((k: any) => !k.read_only);
      if (writeKeys.length > 0) {
        findings.push({ id: 'ac-write-deploy-keys', category: 'access-control', severity: 'medium', title: 'Deploy keys with write access', description: `${writeKeys.length} deploy key(s) have write access to the repository.`, recommendation: 'Review deploy keys and use read-only keys where possible.', soc2Control: 'CC6.1', currentValue: writeKeys.length });
      }
      const oneYearAgo = new Date(); oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
      const oldKeys = deployKeys.filter((k: any) => new Date(k.created_at) < oneYearAgo);
      if (oldKeys.length > 0) {
        findings.push({ id: 'ac-old-deploy-keys', category: 'access-control', severity: 'low', title: 'Old deploy keys detected', description: `${oldKeys.length} deploy key(s) are over 1 year old.`, recommendation: 'Rotate deploy keys periodically. Remove unused keys.', soc2Control: 'CC6.1', currentValue: oldKeys.length });
      }
    } catch { /* May not have permission */ }

    try {
      const { data: webhooks } = await octokit.repos.listWebhooks({ owner, repo, per_page: 100 });
      const insecureWebhooks = webhooks.filter((w: any) => w.config.url && !w.config.url.startsWith('https://'));
      if (insecureWebhooks.length > 0) {
        findings.push({ id: 'ac-insecure-webhooks', category: 'access-control', severity: 'high', title: 'Insecure webhook URLs', description: `${insecureWebhooks.length} webhook(s) use non-HTTPS URLs.`, recommendation: 'Update webhooks to use HTTPS URLs only.', soc2Control: 'CC6.7', currentValue: insecureWebhooks.length, expectedValue: 0 });
      }
      const webhooksWithoutSecret = webhooks.filter((w: any) => !w.config.secret);
      if (webhooksWithoutSecret.length > 0) {
        findings.push({ id: 'ac-webhooks-no-secret', category: 'access-control', severity: 'medium', title: 'Webhooks without secret validation', description: `${webhooksWithoutSecret.length} webhook(s) don't have a secret configured.`, recommendation: 'Configure webhook secrets to validate incoming payloads.', soc2Control: 'CC6.7', currentValue: webhooksWithoutSecret.length, expectedValue: 0 });
      }
    } catch { /* May not have permission */ }

  } catch (error) {
    console.error('Error checking access control:', error);
    throw error;
  }

  return findings;
}
