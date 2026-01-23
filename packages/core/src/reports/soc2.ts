import { RepoScanResult, SOC2Report, SOC2Control, SecurityFinding } from '../types';

const SOC2_CONTROLS: Record<string, { name: string; description: string }> = {
  'CC6.1': { name: 'Logical and Physical Access Controls', description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets.' },
  'CC6.2': { name: 'User Access Management', description: 'Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.' },
  'CC6.7': { name: 'Data Transmission Protection', description: 'The entity restricts the transmission, movement, and removal of information to authorized internal and external users.' },
  'CC7.1': { name: 'Vulnerability Management', description: 'To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in vulnerabilities.' },
  'CC7.4': { name: 'Security Incident Response', description: 'The entity responds to identified security incidents by executing a defined incident response program.' },
  'CC8.1': { name: 'Change Management', description: 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.' },
};

export function generateSOC2Report(scanResults: RepoScanResult[]): SOC2Report {
  const controlFindings: Record<string, SecurityFinding[]> = {};
  const controlEvidence: Record<string, string[]> = {};

  for (const controlId of Object.keys(SOC2_CONTROLS)) {
    controlFindings[controlId] = [];
    controlEvidence[controlId] = [];
  }

  for (const result of scanResults) {
    for (const finding of result.findings) {
      if (finding.soc2Control && controlFindings[finding.soc2Control]) {
        controlFindings[finding.soc2Control].push({ ...finding, description: `[${result.repository.fullName}] ${finding.description}` });
      }
    }

    const repoName = result.repository.fullName;
    if (!result.findings.some(f => f.id === 'bp-not-enabled')) controlEvidence['CC6.1'].push(`${repoName}: Branch protection is enabled on default branch.`);
    if (!result.findings.some(f => f.id === 'sf-no-dependabot-alerts')) controlEvidence['CC7.1'].push(`${repoName}: Dependabot alerts are enabled for vulnerability detection.`);
    if (!result.findings.some(f => f.id === 'sf-no-code-scanning')) controlEvidence['CC7.1'].push(`${repoName}: Code scanning is configured for security analysis.`);
    if (!result.findings.some(f => f.id === 'sf-no-security-policy')) controlEvidence['CC7.4'].push(`${repoName}: Security policy (SECURITY.md) is in place.`);
    if (!result.findings.some(f => f.id === 'sf-no-secret-scanning')) controlEvidence['CC6.7'].push(`${repoName}: Secret scanning is enabled to prevent credential leaks.`);
  }

  const controls: SOC2Control[] = Object.entries(SOC2_CONTROLS).map(([id, info]) => {
    const findings = controlFindings[id];
    const evidence = controlEvidence[id];
    const criticalOrHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    let status: 'compliant' | 'partial' | 'non-compliant';
    if (criticalOrHigh.length === 0 && findings.length <= 2) status = 'compliant';
    else if (criticalOrHigh.length === 0) status = 'partial';
    else status = 'non-compliant';
    return { id, name: info.name, description: info.description, status, findings, evidence };
  });

  const compliantCount = controls.filter(c => c.status === 'compliant').length;
  const partialCount = controls.filter(c => c.status === 'partial').length;
  const overallCompliance = Math.round(((compliantCount + partialCount * 0.5) / controls.length) * 100);

  return { generatedAt: new Date(), repositories: scanResults.map(r => r.repository.fullName), controls, overallCompliance };
}

export function formatSOC2ReportMarkdown(report: SOC2Report): string {
  const lines: string[] = [];
  lines.push('# SOC 2 Compliance Report', '', `**Generated:** ${report.generatedAt.toISOString()}`, `**Repositories Scanned:** ${report.repositories.length}`, `**Overall Compliance:** ${report.overallCompliance}%`, '', '---', '', '## Control Summary', '', '| Control | Name | Status |', '|---------|------|--------|');
  for (const control of report.controls) {
    const statusEmoji = control.status === 'compliant' ? '✅' : control.status === 'partial' ? '⚠️' : '❌';
    lines.push(`| ${control.id} | ${control.name} | ${statusEmoji} ${control.status} |`);
  }
  lines.push('', '---', '', '## Detailed Findings', '');
  for (const control of report.controls) {
    lines.push(`### ${control.id}: ${control.name}`, '', `> ${control.description}`, '', `**Status:** ${control.status.toUpperCase()}`, '');
    if (control.evidence.length > 0) {
      lines.push('**Evidence of Compliance:**');
      for (const evidence of control.evidence) lines.push(`- ${evidence}`);
      lines.push('');
    }
    if (control.findings.length > 0) {
      lines.push('**Findings Requiring Attention:**', '');
      for (const finding of control.findings) {
        const severityEmoji = finding.severity === 'critical' ? '🔴' : finding.severity === 'high' ? '🟠' : finding.severity === 'medium' ? '🟡' : '🔵';
        lines.push(`- ${severityEmoji} **${finding.title}** (${finding.severity})`, `  - ${finding.description}`, `  - *Recommendation:* ${finding.recommendation}`, '');
      }
    } else {
      lines.push('*No findings for this control.*', '');
    }
    lines.push('---', '');
  }
  lines.push('## Repositories Included', '');
  for (const repo of report.repositories) lines.push(`- ${repo}`);
  return lines.join('\n');
}

export function formatSOC2ReportJSON(report: SOC2Report): string {
  return JSON.stringify(report, null, 2);
}
