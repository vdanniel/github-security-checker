import { Octokit } from '@octokit/rest';
import { SecurityFinding } from '../types';

export async function checkSecurityFeatures(
  octokit: Octokit,
  owner: string,
  repo: string
): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  try {
    // Get repository details
    await octokit.repos.get({ owner, repo });

    // Check for security policy (SECURITY.md)
    try {
      await octokit.repos.getContent({
        owner,
        repo,
        path: 'SECURITY.md',
      });
    } catch {
      findings.push({
        id: 'sf-no-security-policy',
        category: 'security-features',
        severity: 'medium',
        title: 'No security policy',
        description: 'Repository lacks a SECURITY.md file for vulnerability reporting.',
        recommendation: 'Create a SECURITY.md file with instructions for reporting security vulnerabilities.',
        documentationUrl: 'https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository',
        soc2Control: 'CC7.4',
      });
    }

    // Check vulnerability alerts (Dependabot alerts)
    try {
      await octokit.repos.checkVulnerabilityAlerts({
        owner,
        repo,
      });
      // If we get here without error, alerts are enabled
    } catch (error: any) {
      if (error.status === 404) {
        findings.push({
          id: 'sf-no-dependabot-alerts',
          category: 'security-features',
          severity: 'high',
          title: 'Dependabot alerts disabled',
          description: 'Dependabot vulnerability alerts are not enabled.',
          recommendation: 'Enable Dependabot alerts to receive notifications about vulnerable dependencies.',
          documentationUrl: 'https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts',
          soc2Control: 'CC7.1',
        });
      }
    }

    // Check for Dependabot config
    try {
      await octokit.repos.getContent({
        owner,
        repo,
        path: '.github/dependabot.yml',
      });
    } catch {
      findings.push({
        id: 'sf-no-dependabot-config',
        category: 'security-features',
        severity: 'medium',
        title: 'Dependabot version updates not configured',
        description: 'No dependabot.yml configuration file found.',
        recommendation: 'Create .github/dependabot.yml to enable automatic dependency updates.',
        documentationUrl: 'https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuring-dependabot-version-updates',
        soc2Control: 'CC7.1',
      });
    }

    // Check for CodeQL / code scanning workflow
    let hasCodeScanning = false;
    try {
      const { data: workflows } = await octokit.actions.listRepoWorkflows({
        owner,
        repo,
      });
      hasCodeScanning = workflows.workflows.some(
        (w) => w.name.toLowerCase().includes('codeql') || 
               w.path.includes('codeql')
      );
    } catch {
      // Actions might not be enabled
    }

    if (!hasCodeScanning) {
      findings.push({
        id: 'sf-no-code-scanning',
        category: 'security-features',
        severity: 'high',
        title: 'Code scanning not configured',
        description: 'No CodeQL or code scanning workflow detected.',
        recommendation: 'Enable GitHub code scanning with CodeQL to detect security vulnerabilities in code.',
        documentationUrl: 'https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning',
        soc2Control: 'CC7.1',
      });
    }

    // Check secret scanning (only available for certain repo types)
    try {
      await octokit.secretScanning.listAlertsForRepo({
        owner,
        repo,
        state: 'open',
        per_page: 1,
      });
      // If we get here, secret scanning is enabled
    } catch (error: any) {
      if (error.status === 404) {
        findings.push({
          id: 'sf-no-secret-scanning',
          category: 'security-features',
          severity: 'high',
          title: 'Secret scanning not enabled',
          description: 'Secret scanning is not enabled for this repository.',
          recommendation: 'Enable secret scanning to detect accidentally committed secrets.',
          documentationUrl: 'https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning',
          soc2Control: 'CC6.7',
        });
      }
    }

    // Check push protection (secret scanning push protection)
    // This is typically enabled at org level but we note it as a recommendation
    findings.push({
      id: 'sf-push-protection-check',
      category: 'security-features',
      severity: 'info',
      title: 'Verify push protection is enabled',
      description: 'Secret scanning push protection blocks commits containing secrets.',
      recommendation: 'Enable push protection in Settings → Code security to block secrets before they are committed.',
      documentationUrl: 'https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations',
      soc2Control: 'CC6.7',
    });

  } catch (error) {
    console.error('Error checking security features:', error);
    throw error;
  }

  return findings;
}

export async function checkDependencyAlerts(
  octokit: Octokit,
  owner: string,
  repo: string
): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  try {
    // Get Dependabot alerts
    const { data: alerts } = await octokit.dependabot.listAlertsForRepo({
      owner,
      repo,
      state: 'open',
      per_page: 100,
    });

    const criticalAlerts = alerts.filter(a => a.security_vulnerability?.severity === 'critical');
    const highAlerts = alerts.filter(a => a.security_vulnerability?.severity === 'high');

    if (criticalAlerts.length > 0) {
      findings.push({
        id: 'dep-critical-vulns',
        category: 'dependencies',
        severity: 'critical',
        title: `${criticalAlerts.length} critical vulnerability alert(s)`,
        description: `Repository has ${criticalAlerts.length} unresolved critical Dependabot alerts.`,
        recommendation: 'Review and remediate critical Dependabot alerts immediately.',
        documentationUrl: 'https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts',
        soc2Control: 'CC7.1',
        currentValue: criticalAlerts.length,
        expectedValue: 0,
      });
    }

    if (highAlerts.length > 0) {
      findings.push({
        id: 'dep-high-vulns',
        category: 'dependencies',
        severity: 'high',
        title: `${highAlerts.length} high severity vulnerability alert(s)`,
        description: `Repository has ${highAlerts.length} unresolved high severity Dependabot alerts.`,
        recommendation: 'Review and remediate high severity Dependabot alerts.',
        documentationUrl: 'https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts',
        soc2Control: 'CC7.1',
        currentValue: highAlerts.length,
        expectedValue: 0,
      });
    }

  } catch (error: any) {
    // Dependabot alerts might not be accessible (404) or disabled (403)
    if (error.status !== 404 && error.status !== 403) {
      console.error('Error checking dependency alerts:', error);
    }
  }

  return findings;
}
