import * as vscode from 'vscode';
import { GitHubSecurityScanner, SecurityFixer } from '@ghsec/core';
import { SecurityTreeProvider } from './treeProvider';
import { ResultsPanel } from './resultsPanel';
import { ScanResult, AvailableRepo } from './types';

const TOKEN_KEY = 'ghsec.github-token';

let scanner: GitHubSecurityScanner | null = null;
let fixer: SecurityFixer | null = null;
let treeProvider: SecurityTreeProvider;
let results: ScanResult[] = [];
let secretStorage: vscode.SecretStorage;

export function activate(context: vscode.ExtensionContext) {
  console.log('GitHub Security Checker activated');

  // Use VS Code's secure secret storage for the token
  secretStorage = context.secrets;

  treeProvider = new SecurityTreeProvider();
  vscode.window.registerTreeDataProvider('ghsecView', treeProvider);

  context.subscriptions.push(
    vscode.commands.registerCommand('ghsec.connect', connectCommand),
    vscode.commands.registerCommand('ghsec.scan', scanCommand),
    vscode.commands.registerCommand('ghsec.showResults', showResultsCommand),
    vscode.commands.registerCommand('ghsec.generateReport', generateReportCommand),
    vscode.commands.registerCommand('ghsec.fixFinding', fixFindingCommand),
    vscode.commands.registerCommand('ghsec.disconnect', disconnectCommand)
  );

  // Try to restore connection from stored token
  restoreConnection();
}

async function restoreConnection() {
  const storedToken = await secretStorage.get(TOKEN_KEY);
  if (storedToken) {
    try {
      scanner = new GitHubSecurityScanner({ token: storedToken });
      fixer = new SecurityFixer(storedToken);
      const repos = await fetchRepos(storedToken);
      treeProvider.setConnected(true, repos.length);
      treeProvider.refresh();
    } catch {
      // Token invalid or expired, clear it
      await secretStorage.delete(TOKEN_KEY);
    }
  }
}

async function connectCommand() {
  const inputToken = await vscode.window.showInputBox({
    prompt: 'Enter your GitHub Personal Access Token',
    password: true,
    placeHolder: 'ghp_xxxxxxxxxxxx',
    ignoreFocusOut: true
  });

  if (!inputToken) {
    return;
  }

  try {
    scanner = new GitHubSecurityScanner({ token: inputToken });
    fixer = new SecurityFixer(inputToken);

    // Test connection by fetching repos
    const repos = await fetchRepos(inputToken);
    
    // Store token securely (never in settings or plain text)
    await secretStorage.store(TOKEN_KEY, inputToken);
    
    vscode.window.showInformationMessage(
      `Connected to GitHub! ${repos.length} repositories available.`
    );
    
    treeProvider.setConnected(true, repos.length);
    treeProvider.refresh();
  } catch (err: any) {
    vscode.window.showErrorMessage(`Failed to connect: ${err.message}`);
    scanner = null;
    fixer = null;
  }
}

async function disconnectCommand() {
  await secretStorage.delete(TOKEN_KEY);
  scanner = null;
  fixer = null;
  results = [];
  treeProvider.setConnected(false, 0);
  treeProvider.setResults([]);
  treeProvider.refresh();
  vscode.window.showInformationMessage('Disconnected from GitHub. Token removed.');
}

async function fetchRepos(token: string): Promise<AvailableRepo[]> {
  const tempScanner = new GitHubSecurityScanner({ token });
  return tempScanner.listAvailableRepos();
}

async function scanCommand() {
  if (!scanner) {
    vscode.window.showErrorMessage('Not connected to GitHub. Run "GitHub Security: Connect" first.');
    return;
  }

  const storedToken = await secretStorage.get(TOKEN_KEY);
  if (!storedToken) {
    vscode.window.showErrorMessage('Token not found. Please reconnect.');
    return;
  }

  const repos = await fetchRepos(storedToken);
  
  const selected = await vscode.window.showQuickPick(
    repos.map(r => ({ label: r.fullName, repo: r })),
    {
      canPickMany: true,
      placeHolder: 'Select repositories to scan'
    }
  );

  if (!selected || selected.length === 0) {
    return;
  }

  await vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: 'Scanning repositories...',
    cancellable: false
  }, async (progress) => {
    results = [];
    const total = selected.length;

    for (let i = 0; i < selected.length; i++) {
      const repo = selected[i].repo;
      progress.report({ 
        message: `${repo.fullName} (${i + 1}/${total})`,
        increment: (100 / total)
      });

      try {
        const result = await scanner!.scanRepository(repo.owner, repo.name);
        results.push(result as ScanResult);
      } catch (err: any) {
        vscode.window.showWarningMessage(`Failed to scan ${repo.fullName}: ${err.message}`);
      }
    }

    treeProvider.setResults(results);
    treeProvider.refresh();
  });

  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  const avgScore = Math.round(results.reduce((sum, r) => sum + r.score, 0) / results.length);

  vscode.window.showInformationMessage(
    `Scan complete! ${results.length} repos, ${totalFindings} findings, avg score: ${avgScore}/100`
  );

  // Auto-show results panel (token retrieved securely when needed)
  const currentToken = await secretStorage.get(TOKEN_KEY);
  if (currentToken && fixer) {
    ResultsPanel.createOrShow(results, fixer);
  }
}

function showResultsCommand() {
  if (results.length === 0) {
    vscode.window.showInformationMessage('No scan results. Run a scan first.');
    return;
  }

  if (fixer) {
    ResultsPanel.createOrShow(results, fixer);
  }
}

async function generateReportCommand() {
  if (results.length === 0) {
    vscode.window.showInformationMessage('No scan results. Run a scan first.');
    return;
  }

  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(`soc2-report-${new Date().toISOString().split('T')[0]}.json`),
    filters: { 'JSON': ['json'] }
  });

  if (!uri) return;

  const report = {
    generatedAt: new Date().toISOString(),
    repositoriesScanned: results.length,
    results: results,
    soc2Summary: generateSOC2Summary(results)
  };

  await vscode.workspace.fs.writeFile(uri, Buffer.from(JSON.stringify(report, null, 2)));
  vscode.window.showInformationMessage(`SOC 2 report saved to ${uri.fsPath}`);
}

function generateSOC2Summary(results: ScanResult[]) {
  const controlFindings: Record<string, any[]> = {
    'CC6.1': [], 'CC6.2': [], 'CC6.7': [], 'CC7.1': [], 'CC7.4': [], 'CC8.1': []
  };

  results.forEach(result => {
    result.findings.forEach(finding => {
      if (finding.soc2Control && controlFindings[finding.soc2Control]) {
        controlFindings[finding.soc2Control].push({
          ...finding,
          repo: result.repository.fullName
        });
      }
    });
  });

  return Object.entries(controlFindings).map(([id, findings]) => {
    const criticalOrHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    let status: string;
    
    if (criticalOrHigh.length === 0 && findings.length <= 2) {
      status = 'compliant';
    } else if (criticalOrHigh.length === 0) {
      status = 'partial';
    } else {
      status = 'non-compliant';
    }

    return { controlId: id, status, findingsCount: findings.length, findings };
  });
}

async function fixFindingCommand(finding?: any, repoFullName?: string) {
  if (!fixer) {
    vscode.window.showErrorMessage('Not connected to GitHub.');
    return;
  }

  if (!finding || !repoFullName) {
    vscode.window.showErrorMessage('No finding selected.');
    return;
  }

  const confirm = await vscode.window.showWarningMessage(
    `Apply fix for "${finding.title}" on ${repoFullName}?`,
    { modal: true },
    'Yes, Fix It'
  );

  if (confirm !== 'Yes, Fix It') return;

  const [owner, repo] = repoFullName.split('/');
  const result = results.find(r => r.repository.fullName === repoFullName);
  const branch = result?.repository.defaultBranch || 'main';

  try {
    const fixResult = await fixer.fixFinding(owner, repo, finding.id, branch);
    
    if (fixResult.success) {
      vscode.window.showInformationMessage(`✅ ${fixResult.message}`);
      
      // Rescan the repo
      if (scanner) {
        const newResult = await scanner.scanRepository(owner, repo);
        results = results.map(r => 
          r.repository.fullName === repoFullName ? newResult as ScanResult : r
        );
        treeProvider.setResults(results);
        treeProvider.refresh();
        ResultsPanel.updateResults(results);
      }
    } else {
      vscode.window.showErrorMessage(`Fix failed: ${fixResult.message}`);
    }
  } catch (err: any) {
    vscode.window.showErrorMessage(`Fix failed: ${err.message}`);
  }
}

export function deactivate() {}
