const core = require('@actions/core');
const github = require('@actions/github');
const https = require('https');

const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const SEVERITY_ICON = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' };

function getSeverity(f) {
  return (f.severity || f.check_severity || '').toUpperCase();
}

function sevBadge(f) {
  const s = getSeverity(f);
  return s ? `${SEVERITY_ICON[s] || '⚪'} ${s}` : '';
}

function L(c = '─', n = 72) { return '  ' + c.repeat(n); }
function blank() { core.info(''); }
function divider() { core.info(L()); }
function heading(t) {
  blank();
  core.info(L('═'));
  core.info(`  ${t}`);
  core.info(L('═'));
  blank();
}

async function run() {
  try {
    const apiKey = core.getInput('api-key', { required: true });
    const orgId = core.getInput('org-id', { required: true });
    let apiUrl = core.getInput('api-url', { required: true });
    const failOn = core.getInput('fail-on') || 'HIGH';

    // Auto-route to the streaming endpoint
    if (apiUrl.endsWith('/scan')) {
      apiUrl = apiUrl + '/stream';
    } else if (!apiUrl.endsWith('/stream')) {
      apiUrl = apiUrl + '/scan/stream';
    }

    const ctx = github.context;
    const repoName = `${ctx.repo.owner}/${ctx.repo.repo}`;
    const branch = ctx.ref.replace('refs/heads/', '');
    const sha = ctx.sha;
    const shortSha = sha.slice(0, 7);
    const scannedAt = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
    const commitMessage = ctx.payload.head_commit?.message || '';

    const repoToken = core.getInput('repo-token') || process.env.GITHUB_TOKEN || '';
    const repoId = String(ctx.payload.repository?.id || '');

    const payload = JSON.stringify({
      org_id: orgId,
      repo_name: repoName,
      branch,
      commit_sha: sha,
      commit_message: commitMessage,
      repo_token: repoToken,
      repo_id: repoId,
      repo_host: 'github',
    });

    const url = new URL(apiUrl);
    const options = {
      hostname: url.hostname,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'Content-Length': Buffer.byteLength(payload),
      },
    };

    blank();
    core.info(L('━'));
    core.info('  ⚓  SECONDBOAT  —  IaC SECURITY SCAN REPORT');
    core.info(L('━'));
    blank();
    core.info(`    Repository  : ${repoName}`);
    core.info(`    Branch      : ${branch}`);
    core.info(`    Commit      : ${shortSha}`);
    core.info(`    Scanned At  : ${scannedAt}`);
    core.info(`    Fail On     : ${failOn}+`);
    blank();
    core.info('  [📡] Connecting to SecondBoat Scanner...');

    // ── The Real-Time SSE Stream Parser ──────────────────────────────────────────
    const body = await new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let buffer = '';

        if (res.statusCode !== 200) {
          let errData = '';
          res.on('data', chunk => errData += chunk);
          res.on('end', () => reject(new Error(`HTTP ${res.statusCode}: ${errData}`)));
          return;
        }

        res.on('data', chunk => {
          buffer += chunk.toString();

          // SSE messages end with \n\n. Parse complete messages from the buffer.
          let boundary = buffer.indexOf('\n\n');
          while (boundary !== -1) {
            const message = buffer.slice(0, boundary);
            buffer = buffer.slice(boundary + 2); // Remove parsed message from buffer

            let eventType = 'message';
            let eventData = '';

            const lines = message.split('\n');
            for (const line of lines) {
              if (line.startsWith('event:')) eventType = line.replace('event:', '').trim();
              else if (line.startsWith('data:')) eventData = line.replace('data:', '').trim();
            }

            if (eventData) {
              try {
                // Parse the outer JSON wrapper from FastAPI
                const parsed = JSON.parse(eventData);
                const actualData = parsed.data;

                // Handle the different real-time event types
                if (eventType === 'accepted') {
                  core.info(`  [🚀] ${actualData.message}`);
                } else if (eventType === 'info' || eventType === 'success') {
                  // Print real-time progress logs from the Lambda!
                  core.info(`  [⏳] ${actualData}`);
                } else if (eventType === 'error') {
                  // Print real-time errors
                  core.warning(`  [⚠️] ${actualData.message || actualData}`);
                } else if (eventType === 'result') {
                  // The scan is completely finished! Resolve the promise with the final payload
                  core.info('  [✅] Scan process completed. Formatting report...');
                  resolve(actualData);
                }
              } catch (e) {
                // Ignore parsing errors for malformed chunks
              }
            }
            boundary = buffer.indexOf('\n\n');
          }
        });

        res.on('end', () => {
          // If the stream closes before we get the 'result' event, something crashed heavily
          reject(new Error('Connection closed by API Gateway before final result was received.'));
        });
      });

      req.on('error', reject);
      req.write(payload);
      req.end();
    });

    core.debug(`[SecondBoat] Response keys: ${Object.keys(body).join(', ')}`);

    if (body.status === 'no_iac') {
      core.warning('  ⚠️   No IaC files detected in this repository');
      core.setOutput('status', 'no_iac');
      core.setOutput('total_failed', '0');
      return;
    }

    // ── Field paths — mapping to the newly updated Lambda return schema ────
    const secFindings = body.checkov_findings || body.findings || [];
    const secPassed = body.total_checkov_passed ?? 0;
    const secFailed = body.total_checkov_failed ?? 0;
    const secTotal = secPassed + secFailed;

    const govFindings = body.governance_findings || [];
    const govPassed = body.total_governance_passed ?? 0;
    const govFailed = body.total_governance_failed ?? 0;
    const govTotal = govPassed + govFailed;

    // ══════════════════════════════════════════════════════════════════════════
    //  SECTION 1 — SECURITY FINDINGS
    // ══════════════════════════════════════════════════════════════════════════
    heading('SECTION 1 of 2  ·  SECURITY FINDINGS');
    core.info(`    ✅  Passed : ${secPassed}    ❌  Failed : ${secFailed}    📊  Total : ${secTotal}`);

    if (secFailed === 0) {
      blank();
      core.info('  🎉  All security checks passed — no violations found');
    } else {
      blank();
      const failedSec = secFindings.filter(f => !f.status || f.status === 'FAILED');
      failedSec.forEach((f, idx) => {
        const num = String(idx + 1).padStart(2, '0');
        const sev = sevBadge(f);
        const location = [
          f.file_path || '',
          f.line_start ? `:${f.line_start}` : '',
          f.line_end && f.line_end !== f.line_start ? `-${f.line_end}` : '',
        ].join('');

        divider();
        core.info(`  [${num}]  ${f.check_id || 'N/A'}${sev ? `   ${sev}` : ''}`);
        divider();
        core.info(`         Check     : ${f.check_name || 'N/A'}`);
        core.info(`         Severity  : ${sev || 'N/A'}`);
        core.info(`         Resource  : ${f.resource || 'N/A'}`);
        core.info(`         Framework : ${f.framework || 'N/A'}`);
        core.info(`         File      : ${location || 'N/A'}`);
        blank();
      });
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  SECTION 2 — GOVERNANCE FINDINGS
    // ══════════════════════════════════════════════════════════════════════════
    heading('SECTION 2 of 2  ·  GOVERNANCE FINDINGS');
    core.info(`    ✅  Passed : ${govPassed}    ❌  Failed : ${govFailed}    📊  Total : ${govTotal}`);

    if (govTotal === 0) {
      blank();
      core.info('  ℹ️   No governance policies configured for this repository');
    } else if (govFailed === 0) {
      blank();
      core.info('  🎉  All governance policies passed');
    } else {
      blank();
      const failedGov = govFindings.filter(f => f.status === 'FAILED');
      const sorted = [...failedGov].sort((a, b) =>
        SEVERITY_ORDER.indexOf(getSeverity(b)) - SEVERITY_ORDER.indexOf(getSeverity(a))
      );

      sorted.forEach((f, idx) => {
        const num = String(idx + 1).padStart(2, '0');
        const sev = sevBadge(f);

        divider();
        core.info(`  [${num}]  ${f.policy_title || f.check_id || 'N/A'}${sev ? `   ${sev}` : ''}`);
        divider();
        core.info(`         Resource      : ${f.resource || 'N/A'}`);
        core.info(`         Scope         : ${f.scope || 'N/A'}`);
        core.info(`         Status/Reason : ${f.reason || 'N/A'}`);
        blank();
      });
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  SUMMARY
    // ══════════════════════════════════════════════════════════════════════════
    const totalFailed = secFailed + govFailed;
    const totalPassed = secPassed + govPassed;

    blank();
    core.info(L('━'));
    core.info('  SCAN SUMMARY');
    core.info(L('━'));
    blank();
    core.info(`    ✅  Passed         : ${totalPassed}`);
    core.info(`    ❌  Failed         : ${totalFailed}`);
    core.info(`    📊  Total Checks   : ${totalPassed + totalFailed}`);
    core.info(`    🎯  Fail Threshold : ${failOn}`);

    if (govFailed > 0) {
      blank();
      core.info('    Governance Severity Breakdown:');
      const failedGov = govFindings.filter(f => f.status === 'FAILED');
      [...SEVERITY_ORDER].reverse().forEach(sev => {
        const count = failedGov.filter(f => getSeverity(f) === sev).length;
        if (count) core.info(`      ${SEVERITY_ICON[sev]}  ${sev.padEnd(8)} : ${count}`);
      });
    }

    blank();
    core.info(L('━'));
    blank();

    // ── FAIL GATE ─────────────────────────────────────────────────────────────
    const shouldFailSec = secFindings.some(f =>
      (!f.status || f.status === 'FAILED') &&
      SEVERITY_ORDER.indexOf(getSeverity(f)) >= SEVERITY_ORDER.indexOf(failOn)
    );

    const shouldFailGov = govFindings.some(f =>
      f.status === 'FAILED' &&
      SEVERITY_ORDER.indexOf(getSeverity(f)) >= SEVERITY_ORDER.indexOf(failOn)
    );

    if (failOn !== 'none' && (shouldFailSec || shouldFailGov)) {
      core.setFailed(`❌  SecondBoat found violations at or above ${failOn} severity`);
    } else if (totalFailed > 0) {
      core.warning(`⚠️   Violations found but all below ${failOn} threshold — pipeline continues`);
    }

    core.setOutput('status', body.status);
    core.setOutput('total_failed', String(totalFailed));

  } catch (err) {
    core.setFailed(`SecondBoat scan failed: ${err.message}`);
  }
}

run();