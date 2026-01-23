import { NextRequest, NextResponse } from 'next/server';
import { GitHubSecurityScanner } from '@ghsec/core';

export async function POST(request: NextRequest) {
  try {
    const { token } = await request.json();

    if (!token) {
      return NextResponse.json(
        { error: 'Token is required' },
        { status: 400 }
      );
    }

    const scanner = new GitHubSecurityScanner({
      token,
      severityThreshold: 'low',
    });

    const repos = await scanner.listAvailableRepos();

    return NextResponse.json({ repos });
  } catch (error: any) {
    console.error('Error fetching repos:', error);
    return NextResponse.json(
      { error: error.message || 'Failed to fetch repositories' },
      { status: 500 }
    );
  }
}
