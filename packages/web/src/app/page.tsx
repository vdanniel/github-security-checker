'use client';

import { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, FileText, Search } from 'lucide-react';

interface ScanResult {
  repository: {
    fullName: string;
    visibility: string;
    defaultBranch: string;
    url: string;
  };
  score: number;
  findings: Array<{
    id: string;
    category: string;
    severity: string;
    title: string;
    description: string;
    recommendation: string;
    documentationUrl?: string;
  }>;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export default function Home() {
  const [token, setToken] = useState('');
  const [repos, setRepos] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!token || !repos) {
      setError('Please provide both a GitHub token and repository names');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          repos: repos.split('\n').map(r => r.trim()).filter(Boolean),
        }),
      });

      if (!response.ok) {
        throw new Error('Scan failed');
      }

      const data = await response.json();
      setResults(data.results);
    } catch (err: any) {
      setError(err.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600 dark:text-green-400';
    if (score >= 60) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-red-600 dark:text-red-400';
  };

  return (
    <div className="space-y-8">
      {/* Input Section */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
          <Search className="w-5 h-5" />
          Scan Repositories
        </h2>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              GitHub Token
            </label>
            <input
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="ghp_xxxxxxxxxxxx"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Repositories (one per line, owner/repo format)
            </label>
            <textarea
              value={repos}
              onChange={(e) => setRepos(e.target.value)}
              placeholder="octocat/hello-world&#10;myorg/my-repo"
              rows={4}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
            />
          </div>

          {error && (
            <div className="text-red-600 dark:text-red-400 text-sm">{error}</div>
          )}

          <button
            onClick={handleScan}
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium py-2 px-4 rounded-md transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent" />
                Scanning...
              </>
            ) : (
              <>
                <Shield className="w-4 h-4" />
                Scan Repositories
              </>
            )}
          </button>
        </div>
      </div>

      {/* Results Section */}
      {results.length > 0 && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
              <div className="text-sm text-gray-500 dark:text-gray-400">Repositories Scanned</div>
              <div className="text-2xl font-bold text-gray-900 dark:text-white">{results.length}</div>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
              <div className="text-sm text-gray-500 dark:text-gray-400">Total Findings</div>
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {results.reduce((sum, r) => sum + r.findings.length, 0)}
              </div>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
              <div className="text-sm text-gray-500 dark:text-gray-400">Average Score</div>
              <div className={`text-2xl font-bold ${getScoreColor(Math.round(results.reduce((sum, r) => sum + r.score, 0) / results.length))}`}>
                {Math.round(results.reduce((sum, r) => sum + r.score, 0) / results.length)}/100
              </div>
            </div>
          </div>

          {/* Repository Results */}
          {results.map((result) => (
            <div key={result.repository.fullName} className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
              <div className="p-4 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                      {result.repository.fullName}
                    </h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      {result.repository.visibility} • {result.repository.defaultBranch}
                    </p>
                  </div>
                  <div className={`text-2xl font-bold ${getScoreColor(result.score)}`}>
                    {result.score}/100
                  </div>
                </div>
                
                {/* Severity Summary */}
                <div className="flex gap-2 mt-3">
                  {result.summary.critical > 0 && (
                    <span className="px-2 py-1 text-xs font-medium rounded bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
                      {result.summary.critical} Critical
                    </span>
                  )}
                  {result.summary.high > 0 && (
                    <span className="px-2 py-1 text-xs font-medium rounded bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200">
                      {result.summary.high} High
                    </span>
                  )}
                  {result.summary.medium > 0 && (
                    <span className="px-2 py-1 text-xs font-medium rounded bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
                      {result.summary.medium} Medium
                    </span>
                  )}
                  {result.summary.low > 0 && (
                    <span className="px-2 py-1 text-xs font-medium rounded bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                      {result.summary.low} Low
                    </span>
                  )}
                </div>
              </div>

              {/* Findings */}
              {result.findings.length > 0 ? (
                <div className="divide-y divide-gray-200 dark:divide-gray-700">
                  {result.findings.map((finding) => (
                    <div key={finding.id} className="p-4">
                      <div className="flex items-start gap-3">
                        <AlertTriangle className={`w-5 h-5 mt-0.5 ${
                          finding.severity === 'critical' ? 'text-red-500' :
                          finding.severity === 'high' ? 'text-orange-500' :
                          finding.severity === 'medium' ? 'text-yellow-500' : 'text-blue-500'
                        }`} />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-gray-900 dark:text-white">
                              {finding.title}
                            </span>
                            <span className={`px-2 py-0.5 text-xs font-medium rounded ${getSeverityColor(finding.severity)}`}>
                              {finding.severity}
                            </span>
                          </div>
                          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                            {finding.description}
                          </p>
                          <div className="mt-2 p-2 bg-blue-50 dark:bg-blue-900/20 rounded text-sm text-blue-800 dark:text-blue-200">
                            💡 {finding.recommendation}
                          </div>
                          {finding.documentationUrl && (
                            <a
                              href={finding.documentationUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-sm text-blue-600 dark:text-blue-400 hover:underline mt-2 inline-block"
                            >
                              📚 View Documentation
                            </a>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 text-center text-green-600 dark:text-green-400 flex items-center justify-center gap-2">
                  <CheckCircle className="w-5 h-5" />
                  No security issues found!
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
