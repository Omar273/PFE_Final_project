import { describe, it, expect, vi } from 'vitest';
import { fetchFindings } from './defectdojoApi';

describe('fetchFindings', () => {
  it('falls back to rule-based score when ML backend is down', async () => {
    global.fetch = vi.fn((url) => {
      if (url.includes('/api/v2/findings')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ results: [
            { id: 1, title: 'XSS', severity: 'High', cwe: 79, cvssv3_score: 7.5 }
          ], next: null })
        });
      }
      if (url.includes('/predict/batch')) {
        return Promise.resolve({ ok: false, status: 500, text: () => '' });
      }
    });
    const findings = await fetchFindings('test-token');
    expect(findings).toHaveLength(1);
    expect(findings[0].ml_scored).toBeUndefined();   // fallback activé
    expect(findings[0].risk_score).toBeGreaterThan(0);   // rule-based score
  });
});