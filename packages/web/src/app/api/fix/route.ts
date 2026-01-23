import { NextRequest, NextResponse } from 'next/server';
import { SecurityFixer } from '@ghsec/core';

export async function POST(request: NextRequest) {
  try {
    const { token, owner, repo, findingId, branch } = await request.json();

    if (!token || !owner || !repo || !findingId) {
      return NextResponse.json(
        { error: 'Token, owner, repo, and findingId are required' },
        { status: 400 }
      );
    }

    const fixer = new SecurityFixer(token);
    const result = await fixer.fixFinding(owner, repo, findingId, branch);

    return NextResponse.json(result);
  } catch (error: any) {
    console.error('Fix error:', error);
    return NextResponse.json(
      { success: false, error: error.message || 'Fix failed' },
      { status: 500 }
    );
  }
}
