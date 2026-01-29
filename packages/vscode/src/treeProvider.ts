import * as vscode from 'vscode';
import { ScanResult, SOC2_CONTROLS } from './types';

export class SecurityTreeProvider implements vscode.TreeDataProvider<TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private connected = false;
  private repoCount = 0;
  private results: ScanResult[] = [];

  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  setConnected(connected: boolean, repoCount: number): void {
    this.connected = connected;
    this.repoCount = repoCount;
  }

  setResults(results: ScanResult[]): void {
    this.results = results;
  }

  getTreeItem(element: TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeItem): Thenable<TreeItem[]> {
    if (!element) {
      return Promise.resolve(this.getRootItems());
    }

    if (element.contextValue === 'repos-root') {
      return Promise.resolve(this.getRepoItems());
    }

    if (element.contextValue === 'soc2-root') {
      return Promise.resolve(this.getSOC2Items());
    }

    if (element.contextValue === 'repo') {
      return Promise.resolve(this.getFindingItems(element.repoFullName!));
    }

    return Promise.resolve([]);
  }

  private getRootItems(): TreeItem[] {
    if (!this.connected) {
      const item = new TreeItem(
        'Click to connect to GitHub',
        vscode.TreeItemCollapsibleState.None,
        'connect'
      );
      item.command = {
        command: 'ghsec.connect',
        title: 'Connect'
      };
      item.iconPath = new vscode.ThemeIcon('plug');
      return [item];
    }

    const items: TreeItem[] = [];

    // Connection status
    const statusItem = new TreeItem(
      `✓ Connected (${this.repoCount} repos)`,
      vscode.TreeItemCollapsibleState.None,
      'status'
    );
    statusItem.iconPath = new vscode.ThemeIcon('check', new vscode.ThemeColor('charts.green'));
    items.push(statusItem);

    if (this.results.length === 0) {
      const scanItem = new TreeItem(
        'Run a scan to see results',
        vscode.TreeItemCollapsibleState.None,
        'scan-prompt'
      );
      scanItem.command = {
        command: 'ghsec.scan',
        title: 'Scan'
      };
      scanItem.iconPath = new vscode.ThemeIcon('search');
      items.push(scanItem);
    } else {
      // Summary
      const totalFindings = this.results.reduce((sum, r) => sum + r.findings.length, 0);
      const avgScore = Math.round(this.results.reduce((sum, r) => sum + r.score, 0) / this.results.length);
      
      const summaryItem = new TreeItem(
        `Score: ${avgScore}/100 | ${totalFindings} findings`,
        vscode.TreeItemCollapsibleState.None,
        'summary'
      );
      summaryItem.iconPath = new vscode.ThemeIcon('graph');
      items.push(summaryItem);

      // Repositories
      const reposItem = new TreeItem(
        `Repositories (${this.results.length})`,
        vscode.TreeItemCollapsibleState.Expanded,
        'repos-root'
      );
      reposItem.iconPath = new vscode.ThemeIcon('repo');
      items.push(reposItem);

      // SOC 2 Controls
      const soc2Item = new TreeItem(
        'SOC 2 Controls',
        vscode.TreeItemCollapsibleState.Collapsed,
        'soc2-root'
      );
      soc2Item.iconPath = new vscode.ThemeIcon('shield');
      items.push(soc2Item);
    }

    return items;
  }

  private getRepoItems(): TreeItem[] {
    return this.results.map(result => {
      const item = new TreeItem(
        `${result.repository.fullName} (${result.score}/100)`,
        result.findings.length > 0 
          ? vscode.TreeItemCollapsibleState.Collapsed 
          : vscode.TreeItemCollapsibleState.None,
        'repo'
      );
      item.repoFullName = result.repository.fullName;
      item.description = `${result.findings.length} findings`;
      
      if (result.score >= 80) {
        item.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('charts.green'));
      } else if (result.score >= 60) {
        item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('charts.yellow'));
      } else {
        item.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('charts.red'));
      }

      return item;
    });
  }

  private getSOC2Items(): TreeItem[] {
    const controlFindings: Record<string, number> = {};
    
    this.results.forEach(result => {
      result.findings.forEach(finding => {
        if (finding.soc2Control) {
          controlFindings[finding.soc2Control] = (controlFindings[finding.soc2Control] || 0) + 1;
        }
      });
    });

    return Object.entries(SOC2_CONTROLS).map(([id, info]) => {
      const count = controlFindings[id] || 0;
      const item = new TreeItem(
        `${id}: ${info.name}`,
        vscode.TreeItemCollapsibleState.None,
        'soc2-control'
      );
      item.description = count === 0 ? '✓ Compliant' : `${count} findings`;
      
      if (count === 0) {
        item.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('charts.green'));
      } else if (count <= 2) {
        item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('charts.yellow'));
      } else {
        item.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('charts.red'));
      }

      return item;
    });
  }

  private getFindingItems(repoFullName: string): TreeItem[] {
    const result = this.results.find(r => r.repository.fullName === repoFullName);
    if (!result) return [];

    return result.findings.map(finding => {
      const item = new TreeItem(
        finding.title,
        vscode.TreeItemCollapsibleState.None,
        'finding'
      );
      item.description = finding.severity;
      item.tooltip = `${finding.description}\n\n💡 ${finding.recommendation}`;
      
      const severityIcon = {
        critical: new vscode.ThemeIcon('error', new vscode.ThemeColor('charts.red')),
        high: new vscode.ThemeIcon('warning', new vscode.ThemeColor('charts.orange')),
        medium: new vscode.ThemeIcon('warning', new vscode.ThemeColor('charts.yellow')),
        low: new vscode.ThemeIcon('info', new vscode.ThemeColor('charts.blue')),
        info: new vscode.ThemeIcon('info')
      };
      item.iconPath = severityIcon[finding.severity] || severityIcon.info;

      return item;
    });
  }
}

class TreeItem extends vscode.TreeItem {
  repoFullName?: string;

  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly contextValue: string
  ) {
    super(label, collapsibleState);
  }
}
