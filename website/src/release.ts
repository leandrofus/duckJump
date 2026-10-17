import { execSync } from 'node:child_process';

export const REPO = process.env.RELEASE_REPO || 'leandrofus/duckJump';
export const FALLBACK_TAG = 'v0.1.7';

export interface ReleaseInfo {
  tag: string;
}

export async function getLatestTag(): Promise<string> {
  // 1. Explicit env var (passed during build or CI)
  if (process.env.PUBLIC_LATEST_TAG) {
    return process.env.PUBLIC_LATEST_TAG.trim();
  }
  if (process.env.LATEST_TAG) {
    return process.env.LATEST_TAG.trim();
  }
  if (process.env.TAG) {
    return process.env.TAG.trim();
  }

  // 2. Try GitHub API if GITHUB_TOKEN or online
  try {
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'duckJump-Website-Build',
    };
    const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    const res = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, {
      headers,
      signal: AbortSignal.timeout(3500),
    });
    if (res.ok) {
      const data = (await res.json()) as { tag_name?: string };
      if (data?.tag_name) {
        return data.tag_name;
      }
    }
  } catch {}

  // 3. Fallback to git describe in the repository
  try {
    const gitTag = execSync('git describe --tags --abbrev=0', {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (gitTag) {
      return gitTag;
    }
  } catch {}

  // 4. Fallback default
  return FALLBACK_TAG;
}
