import * as vscode from 'vscode';
import { SecurityFixer } from '@ghsec/core';
import { ScanResult, SOC2_CONTROLS } from './types';

export class ResultsPanel {
  public static currentPanel: ResultsPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private results: ScanResult[];
  private fixer: SecurityFixer;
  private disposables: vscode.Disposable[] = [];

  private constructor(
    panel: vscode.WebviewPanel,
    results: ScanResult[],
    fixer: SecurityFixer
  ) {
    this.panel = panel;
    this.results = results;
    this.fixer = fixer;

    this.update();

    this.panel.webview.onDidReceiveMessage(
      async (message) => {
        switch (message.command) {
          case 'fix':
            await this.handleFix(message.findingId, message.repoFullName);
            break;
          case 'openSettings':
            vscode.env.openExternal(vscode.Uri.parse(message.url));
            break;
        }
      },
      null,
      this.disposables
    );

    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  public static createOrShow(results: ScanResult[], fixer: SecurityFixer) {
    const column = vscode.window.activeTextEditor?.viewColumn;

    if (ResultsPanel.currentPanel) {
      ResultsPanel.currentPanel.results = results;
      ResultsPanel.currentPanel.panel.reveal(column);
      ResultsPanel.currentPanel.update();
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      'ghsecResults',
      '🛡️ Security Results',
      column || vscode.ViewColumn.One,
      { enableScripts: true, retainContextWhenHidden: true }
    );

    ResultsPanel.currentPanel = new ResultsPanel(panel, results, fixer);
  }

  public static updateResults(results: ScanResult[]) {
    if (ResultsPanel.currentPanel) {
      ResultsPanel.currentPanel.results = results;
      ResultsPanel.currentPanel.update();
    }
  }

  private async handleFix(findingId: string, repoFullName: string) {
    const [owner, repo] = repoFullName.split('/');
    const result = this.results.find(r => r.repository.fullName === repoFullName);
    const branch = result?.repository.defaultBranch || 'main';

    try {
      const fixResult = await this.fixer.fixFinding(owner, repo, findingId, branch);
      
      this.panel.webview.postMessage({
        command: 'fixResult',
        success: fixResult.success,
        message: fixResult.message,
        findingId,
        repoFullName
      });
    } catch (err: any) {
      this.panel.webview.postMessage({
        command: 'fixResult',
        success: false,
        message: err.message,
        findingId,
        repoFullName
      });
    }
  }

  public update() {
    this.panel.webview.html = this.getHtmlContent();
  }

  private getHtmlContent(): string {
    const totalFindings = this.results.reduce((sum, r) => sum + r.findings.length, 0);
    const avgScore = this.results.length > 0 
      ? Math.round(this.results.reduce((sum, r) => sum + r.score, 0) / this.results.length)
      : 0;

    // Calculate SOC 2 control status
    const controlFindings: Record<string, any[]> = {};
    Object.keys(SOC2_CONTROLS).forEach(id => { controlFindings[id] = []; });
    
    this.results.forEach(result => {
      result.findings.forEach(finding => {
        if (finding.soc2Control && controlFindings[finding.soc2Control]) {
          controlFindings[finding.soc2Control].push({
            ...finding,
            repo: result.repository.fullName
          });
        }
      });
    });

    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Results</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: var(--vscode-font-family);
      background: var(--vscode-editor-background);
      color: var(--vscode-editor-foreground);
      padding: 20px;
    }
    .header {
      margin-bottom: 24px;
    }
    .header h1 {
      font-size: 24px;
      margin-bottom: 8px;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .summary-card {
      background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border);
      border-radius: 8px;
      padding: 16px;
    }
    .summary-card .label {
      font-size: 12px;
      opacity: 0.7;
    }
    .summary-card .value {
      font-size: 24px;
      font-weight: bold;
    }
    .score-good { color: #22c55e; }
    .score-warn { color: #eab308; }
    .score-bad { color: #ef4444; }
    .section {
      background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border);
      border-radius: 8px;
      margin-bottom: 16px;
      overflow: hidden;
    }
    .section-header {
      padding: 16px;
      border-bottom: 1px solid var(--vscode-input-border);
      font-weight: 600;
    }
    .control-item, .repo-item {
      padding: 12px 16px;
      border-bottom: 1px solid var(--vscode-input-border);
    }
    .control-item:last-child, .repo-item:last-child {
      border-bottom: none;
    }
    .control-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .badge {
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }
    .badge-compliant { background: #22c55e20; color: #22c55e; }
    .badge-partial { background: #eab30820; color: #eab308; }
    .badge-non-compliant { background: #ef444420; color: #ef4444; }
    .badge-critical { background: #ef444420; color: #ef4444; }
    .badge-high { background: #f9731620; color: #f97316; }
    .badge-medium { background: #eab30820; color: #eab308; }
    .badge-low { background: #3b82f620; color: #3b82f6; }
    .finding {
      background: var(--vscode-editor-background);
      border-radius: 4px;
      padding: 12px;
      margin-top: 8px;
    }
    .finding-title {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .finding-desc {
      margin-top: 8px;
      font-size: 13px;
      opacity: 0.8;
    }
    .finding-rec {
      margin-top: 8px;
      padding: 8px;
      background: #3b82f610;
      border-radius: 4px;
      font-size: 13px;
    }
    .finding-actions {
      margin-top: 12px;
      display: flex;
      gap: 8px;
    }
    button {
      padding: 6px 12px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      display: flex;
      align-items: center;
      gap: 4px;
    }
    .btn-fix {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
    }
    .btn-fix:hover {
      background: var(--vscode-button-hoverBackground);
    }
    .btn-settings {
      background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border);
      color: var(--vscode-editor-foreground);
    }
    .btn-settings:hover {
      background: var(--vscode-list-hoverBackground);
    }
    .repo-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .repo-score {
      font-size: 20px;
      font-weight: bold;
    }
    .empty {
      padding: 24px;
      text-align: center;
      opacity: 0.6;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ GitHub Security Results</h1>
    <p>${this.results.length} repositories scanned</p>
  </div>

  <div class="summary">
    <div class="summary-card">
      <div class="label">Repositories</div>
      <div class="value">${this.results.length}</div>
    </div>
    <div class="summary-card">
      <div class="label">Total Findings</div>
      <div class="value">${totalFindings}</div>
    </div>
    <div class="summary-card">
      <div class="label">Average Score</div>
      <div class="value ${avgScore >= 80 ? 'score-good' : avgScore >= 60 ? 'score-warn' : 'score-bad'}">${avgScore}/100</div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">SOC 2 Control Summary</div>
    ${Object.entries(SOC2_CONTROLS).map(([id, info]) => {
      const findings = controlFindings[id];
      const criticalOrHigh = findings.filter((f: any) => f.severity === 'critical' || f.severity === 'high');
      let status: string, badgeClass: string;
      
      if (criticalOrHigh.length === 0 && findings.length <= 2) {
        status = '✓ Compliant';
        badgeClass = 'badge-compliant';
      } else if (criticalOrHigh.length === 0) {
        status = '⚠ Partial';
        badgeClass = 'badge-partial';
      } else {
        status = '✗ Non-Compliant';
        badgeClass = 'badge-non-compliant';
      }

      return `
        <div class="control-item">
          <div class="control-header">
            <div>
              <strong>${id}</strong>: ${info.name}
              <span class="badge ${badgeClass}">${status}</span>
            </div>
            <div>${findings.length} findings</div>
          </div>
        </div>
      `;
    }).join('')}
  </div>

  ${this.results.map(result => `
    <div class="section">
      <div class="section-header">
        <div class="repo-header">
          <div>
            <strong>${result.repository.fullName}</strong>
            <span style="opacity: 0.6; margin-left: 8px;">${result.repository.visibility}</span>
          </div>
          <div class="repo-score ${result.score >= 80 ? 'score-good' : result.score >= 60 ? 'score-warn' : 'score-bad'}">
            ${result.score}/100
          </div>
        </div>
      </div>
      ${result.findings.length === 0 ? `
        <div class="empty">✓ No security issues found!</div>
      ` : result.findings.map(finding => `
        <div class="repo-item">
          <div class="finding">
            <div class="finding-title">
              <span class="badge badge-${finding.severity}">${finding.severity}</span>
              <strong>${finding.title}</strong>
              ${finding.soc2Control ? `<span class="badge" style="background: #8b5cf620; color: #8b5cf6;">${finding.soc2Control}</span>` : ''}
            </div>
            <div class="finding-desc">${finding.description}</div>
            <div class="finding-rec">💡 ${finding.recommendation}</div>
            <div class="finding-actions">
              <button class="btn-fix" onclick="fix('${finding.id}', '${result.repository.fullName}')">
                🔧 Fix It
              </button>
              <button class="btn-settings" onclick="openSettings('${result.repository.fullName}', '${finding.category}')">
                ⚙️ GitHub Settings
              </button>
            </div>
          </div>
        </div>
      `).join('')}
    </div>
  `).join('')}

  <script>
    const vscode = acquireVsCodeApi();
    
    function fix(findingId, repoFullName) {
      vscode.postMessage({ command: 'fix', findingId, repoFullName });
    }
    
    function openSettings(repoFullName, category) {
      const baseUrl = 'https://github.com/' + repoFullName + '/settings';
      const urls = {
        'branch-protection': baseUrl + '/branches',
        'security-features': baseUrl + '/security_analysis',
        'access-control': baseUrl + '/access',
        'repository-settings': baseUrl
      };
      vscode.postMessage({ command: 'openSettings', url: urls[category] || baseUrl });
    }

    window.addEventListener('message', event => {
      const message = event.data;
      if (message.command === 'fixResult') {
        if (message.success) {
          alert('✅ ' + message.message);
        } else {
          alert('❌ Fix failed: ' + message.message);
        }
      }
    });
  </script>
</body>
</html>`;
  }

  public dispose() {
    ResultsPanel.currentPanel = undefined;
    this.panel.dispose();
    while (this.disposables.length) {
      const d = this.disposables.pop();
      if (d) d.dispose();
    }
  }
}
