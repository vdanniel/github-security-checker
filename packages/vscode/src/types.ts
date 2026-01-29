export interface ScanResult {
  repository: {
    fullName: string;
    visibility: string;
    defaultBranch: string;
    url: string;
  };
  score: number;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface Finding {
  id: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  recommendation: string;
  documentationUrl?: string;
  soc2Control?: string;
}

export interface AvailableRepo {
  owner: string;
  name: string;
  fullName: string;
}

export const SOC2_CONTROLS: Record<string, { name: string; description: string }> = {
  'CC6.1': {
    name: 'Logical and Physical Access Controls',
    description: 'The entity implements logical access security over protected information assets.',
  },
  'CC6.2': {
    name: 'User Access Management',
    description: 'The entity registers and authorizes new internal and external users.',
  },
  'CC6.7': {
    name: 'Data Transmission Protection',
    description: 'The entity restricts transmission and movement of information.',
  },
  'CC7.1': {
    name: 'Vulnerability Management',
    description: 'The entity uses detection procedures to identify configuration vulnerabilities.',
  },
  'CC7.4': {
    name: 'Security Incident Response',
    description: 'The entity responds to identified security incidents.',
  },
  'CC8.1': {
    name: 'Change Management',
    description: 'The entity authorizes, tests, and implements changes to infrastructure and software.',
  },
};
