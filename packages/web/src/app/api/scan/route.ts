import { NextRequest, NextResponse } from 'next/server';
import { GitHubSecurityScanner } from '@ghsec/core';

export async function POST(request: NextRequest) {
  try {
    const { token, repos } = await request.json();

    if (!token || !repos || repos.length === 0) {
      return NextResponse.json(
        { error: 'Token and repos are required' },
        { status: 400 }
      );
    }

    const scanner = new GitHubSecurityScanner({
      token,
      severityThreshold: 'low',
    });

    const results = await scanner.scanMultipleRepos(repos);

    return NextResponse.json({ results });
  } catch (error: any) {
    console.error('Scan error:', error);
    return NextResponse.json(
      { error: error.message || 'Scan failed' },
      { status: 500 }
    );
  }
}
