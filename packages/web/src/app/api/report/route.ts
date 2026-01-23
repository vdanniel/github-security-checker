import { NextRequest, NextResponse } from 'next/server';
import { 
  GitHubSecurityScanner, 
  generateSOC2Report, 
  formatSOC2ReportMarkdown,
  formatSOC2ReportJSON 
} from '@ghsec/core';

export async function POST(request: NextRequest) {
  try {
    const { token, repos, format = 'markdown' } = await request.json();

    if (!token || !repos || repos.length === 0) {
      return NextResponse.json(
        { error: 'Token and repos are required' },
        { status: 400 }
      );
    }

    const scanner = new GitHubSecurityScanner({
      token,
      severityThreshold: 'info',
    });

    const results = await scanner.scanMultipleRepos(repos);
    const report = generateSOC2Report(results);

    if (format === 'json') {
      return NextResponse.json({ report });
    }

    const markdown = formatSOC2ReportMarkdown(report);
    return NextResponse.json({ report, markdown });
  } catch (error: any) {
    console.error('Report error:', error);
    return NextResponse.json(
      { error: error.message || 'Report generation failed' },
      { status: 500 }
    );
  }
}
