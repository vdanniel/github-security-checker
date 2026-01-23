import { z } from 'zod';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type CheckCategory = 
  | 'branch-protection'
  | 'security-features'
  | 'access-control'
  | 'repository-settings'
  | 'secrets'
  | 'dependencies';

export interface SecurityFinding {
  id: string;
  category: CheckCategory;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  documentationUrl?: string;
  soc2Control?: string;
  currentValue?: unknown;
  expectedValue?: unknown;
}

export interface RepoScanResult {
  repository: {
    owner: string;
    name: string;
    fullName: string;
    visibility: 'public' | 'private' | 'internal';
    defaultBranch: string;
    url: string;
  };
  scannedAt: Date;
  findings: SecurityFinding[];
  score: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    passed: number;
  };
}

export interface BranchProtection {
  enabled: boolean;
  requiredStatusChecks: { strict: boolean; contexts: string[]; } | null;
  enforceAdmins: boolean;
  requiredPullRequestReviews: {
    dismissStaleReviews: boolean;
    requireCodeOwnerReviews: boolean;
    requiredApprovingReviewCount: number;
    requireLastPushApproval: boolean;
  } | null;
  restrictions: boolean;
  requiredLinearHistory: boolean;
  allowForcePushes: boolean;
  allowDeletions: boolean;
  requiredConversationResolution: boolean;
  requiredSignatures: boolean;
}

export interface SecuritySettings {
  dependencyGraph: boolean;
  dependabotAlerts: boolean;
  dependabotSecurityUpdates: boolean;
  secretScanning: boolean;
  secretScanningPushProtection: boolean;
  codeScanning: boolean;
  privateVulnerabilityReporting: boolean;
}

export interface SOC2Report {
  generatedAt: Date;
  repositories: string[];
  controls: SOC2Control[];
  overallCompliance: number;
}

export interface SOC2Control {
  id: string;
  name: string;
  description: string;
  status: 'compliant' | 'partial' | 'non-compliant';
  findings: SecurityFinding[];
  evidence: string[];
}

export interface ScannerConfig {
  token: string;
  repos?: string[];
  org?: string;
  includeArchived?: boolean;
  includeForks?: boolean;
  severityThreshold?: Severity;
}

export const ScannerConfigSchema = z.object({
  token: z.string().min(1),
  repos: z.array(z.string()).optional(),
  org: z.string().optional(),
  includeArchived: z.boolean().default(false),
  includeForks: z.boolean().default(false),
  severityThreshold: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('low'),
});
