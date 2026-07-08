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
    const apiUrl = core.getInput('api-url');
    const failOn = core.getInput('fail-on') || 'HIGH';

    const ctx = github.context;
    const repoName = `${ctx.repo.owner}/${ctx.repo.repo}`;
    const branch = ctx.ref.replace('refs/heads/', '');
    const sha = ctx.sha;
    const shortSha = sha.slice(0, 7);
    const scannedAt = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
    const commitMessage = ctx.payload.head_commit?.message || '';

    // repo_token = GITHUB_TOKEN auto-injected by GitHub Actions — no user setup needed
    // repo_id    = numeric repository ID, used for CI-first auto-registration
    const repoToken = core.getInput('repo-token') || process.env.GITHUB_TOKEN || '';
    const repoId = String(ctx.payload.repository?.id || '');

    const payload = JSON.stringify({
      org_id: orgId,
      repo_name: repoName,
      branch,
      commit_sha: sha,
      commit_message: commitMessage,
      repo_token: repoToken,   // GITHUB_TOKEN — Lambda uses this to clone if no App install
      repo_id: repoId,      // numeric repo ID for CI-first auto-registration
      repo_host: 'github',    // tells Lambda which Git host this is
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

    const body = await new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () =>
          res.statusCode !== 200
            ? reject(new Error(`HTTP ${res.statusCode}: ${data}`))
            : resolve(JSON.parse(data))
        );
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

    // ── Field paths — try all known variants ─────────────────────────────────
    const secFindings = body.checkov_findings
      || body.checkov?.findings
      || body.findings
      || [];

    const secPassed = body.total_checkov_passed
      ?? body.checkov?.total_passed
      ?? body.total_passed
      ?? 0;

    const secFailed = body.total_checkov_failed
      ?? body.checkov?.total_failed
      ?? body.total_failed
      ?? 0;

    const secTotal = body.total_checkov_checks
      ?? body.checkov?.total_checks
      ?? body.total_checks
      ?? (secPassed + secFailed);

    const govFindings = body.governance_findings
      || body.governance?.findings
      || [];

    const govPassed = body.total_governance_passed
      ?? body.governance?.total_passed
      ?? 0;

    const govFailed = body.total_governance_failed
      ?? body.governance?.total_failed
      ?? 0;

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
        core.info(`  [${num}]  ${f.policy_title || 'N/A'}${sev ? `   ${sev}` : ''}`);
        divider();
        core.info(`         Resource      : ${f.resource || 'N/A'}`);
        core.info(`         Resource Type : ${f.resource_type || 'N/A'}`);

        // Fallback for older lambda payload or new payload
        const conditions = f.evaluated_conditions || f.failed_conditions || [];

        if (conditions.length > 0) {
          blank();
          core.info(`         Conditions Evaluated:`);
          conditions.forEach(c => {
            const checkIcon = (c.status === 'PASSED') ? '✅' : '❌';
            const checkName = c.check_id || c.key || 'Unknown Check';

            core.info(`           ${checkIcon} ${checkName}`);

            // Only print Expected/Actual details if the check actually failed
            if (c.status !== 'PASSED') {
              core.info(`               Expected : ${c.operator} "${c.expected}"`);
              core.info(`               Actual   : "${c.actual}"`);
            }
          });
        }
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
    const govShouldFail = failOn !== 'none' && govFindings.some(f =>
      f.status === 'FAILED' &&
      SEVERITY_ORDER.indexOf(getSeverity(f)) >= SEVERITY_ORDER.indexOf(failOn)
    );


    if (govShouldFail) {
      core.setFailed(`❌  SecondBoat found governance violations at or above ${failOn} severity`);
    } else if (govFailed > 0) {
      core.warning(`⚠️   Governance violations found but all below ${failOn} threshold — pipeline continues`);
    }


    core.setOutput('status', body.status);
    core.setOutput('total_failed', String(totalFailed));


  } catch (err) {
    core.setFailed(`SecondBoat scan failed: ${err.message}`);
  }
}

run();