const core = require('@actions/core'); 
const github = require('@actions/github');
const https = require('https');

const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const SEVERITY_ICON = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' };

function getSeverity(f) {
  return (f.severity || f.check_severity || 'MEDIUM').toUpperCase();
}

function sevBadge(sevStr) {
  return sevStr ? `${SEVERITY_ICON[sevStr] || '⚪'} ${sevStr}` : '';
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

    if (apiUrl.endsWith('/')) apiUrl = apiUrl.slice(0, -1);
    if (apiUrl.endsWith('/scan')) apiUrl = apiUrl + '/stream';
    else if (!apiUrl.endsWith('/stream') && !apiUrl.endsWith('/scan/stream')) apiUrl = apiUrl + '/scan/stream';

    const ctx = github.context;
    const repoName = `${ctx.repo.owner}/${ctx.repo.repo}`;
    const branch = ctx.ref.replace('refs/heads/', '');
    const sha = ctx.sha;
    const shortSha = sha.slice(0, 7);
    const commitMessage = ctx.payload.head_commit?.message || '';

    const repoToken = core.getInput('repo-token') || process.env.GITHUB_TOKEN || '';
    const repoId = String(ctx.payload.repository?.id || '');

    const payload = JSON.stringify({
      org_id: orgId, repo_name: repoName, branch, commit_sha: sha, 
      commit_message: commitMessage, repo_token: repoToken, repo_id: repoId, repo_host: 'github'
    });

    const url = new URL(apiUrl);
    const options = {
      hostname: url.hostname, path: url.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'Content-Length': Buffer.byteLength(payload) },
    };

    blank();
    core.info(L('━'));
    core.info('  ⚓  SECONDBOAT SCAN REPORT');
    core.info(L('━'));
    blank();
    core.info(`    Repository  : ${repoName}`);
    core.info(`    Branch      : ${branch}`);
    core.info(`    Commit      : ${shortSha}`);
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
          let boundary = buffer.indexOf('\n\n');
          while (boundary !== -1) {
            const message = buffer.slice(0, boundary);
            buffer = buffer.slice(boundary + 2); 
            
            let eventType = 'message';
            let eventData = '';
            for (const line of message.split('\n')) {
              if (line.startsWith('event:')) eventType = line.replace('event:', '').trim();
              else if (line.startsWith('data:')) eventData = line.replace('data:', '').trim();
            }
            
            if (eventData) {
              try {
                const parsed = JSON.parse(eventData);
                const actualData = parsed.data; 
                if (eventType === 'accepted') core.info(`  [🚀] ${actualData.message}`);
                else if (eventType === 'info' || eventType === 'success') core.info(`  [⏳] ${actualData}`);
                else if (eventType === 'error') core.warning(`  [⚠️] ${actualData.message || actualData}`);
                else if (eventType === 'result') {
                  core.info('  [✅] Formatting final report...');
                  resolve(actualData);
                }
              } catch (e) {}
            }
            boundary = buffer.indexOf('\n\n');
          }
        });

        res.on('end', () => reject(new Error('Connection closed prematurely.')));
      });

      req.on('error', reject);
      req.write(payload);
      req.end();
    });

    if (body.status === 'no_iac') {
      core.warning('  ⚠️   No infrastructure files detected in this repository');
      return;
    }

    // ── Field paths ───────────────────────────────────────────────────────────
    const secFindings = body.checkov_findings || [];
    const allGovFindings = body.governance_findings || [];
    
    const cloudGov = allGovFindings.filter(f => f.scope === 'cloud');
    const scGov = allGovFindings.filter(f => f.scope === 'supply_chain');
    
    const cveSummary = body.cve_summary || {};
    const cveCriticals = body.cve_criticals || [];
    const sbomSummary = body.sbom_summary || {};

    let totalFailed = 0;


    // ══════════════════════════════════════════════════════════════════════════
    //  1. CLOUD INFRASTRUCTURE ADVISOR (Grouped & Deduplicated)
    // ══════════════════════════════════════════════════════════════════════════
    heading('1. Cloud Infrastructure Advisor');
    const failedSec = secFindings.filter(f => !f.status || f.status === 'FAILED');
    
    if (failedSec.length === 0) {
      core.info('  🎉  All security checks passed — no infrastructure violations found');
    } else {
      // Group findings by Check ID
      const groupedSec = {};
      failedSec.forEach(f => {
        // Convert CKV_ to SB_
        const rawId = f.check_id || 'UNKNOWN';
        const displayId = rawId.replace(/^CKV_/, 'SB_');
        
        if (!groupedSec[displayId]) {
          groupedSec[displayId] = {
            check_name: f.check_name,
            severity: getSeverity(f),
            resources: []
          };
        }
        
        const loc = [f.file_path || '', f.line_start ? `:${f.line_start}` : ''].join('');
        groupedSec[displayId].resources.push(`- ${f.resource || 'N/A'} (${loc})`);
      });

      // Sort by Severity
      const sortedCheckIds = Object.keys(groupedSec).sort((a, b) => 
        SEVERITY_ORDER.indexOf(groupedSec[b].severity) - SEVERITY_ORDER.indexOf(groupedSec[a].severity)
      );

      totalFailed += sortedCheckIds.length;

      sortedCheckIds.forEach((checkId, idx) => {
        const group = groupedSec[checkId];
        const num = String(idx + 1).padStart(2, '0');
        const sev = sevBadge(group.severity);

        divider();
        core.info(`  [${num}]  ${checkId}   ${sev}`);
        divider();
        core.info(`         Check     : ${group.check_name || 'N/A'}`);
        core.info(`         Resources : `);
        
        // List up to 5 resources so the console doesn't get spammed, summarize the rest
        const maxDisplay = 5;
        group.resources.slice(0, maxDisplay).forEach(r => core.info(`                     ${r}`));
        if (group.resources.length > maxDisplay) {
          core.info(`                     ... and ${group.resources.length - maxDisplay} more resources`);
        }
        blank();
      });
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  2. CLOUD INFRASTRUCTURE VIOLATIONS (Custom Cloud Policies)
    // ══════════════════════════════════════════════════════════════════════════
    heading('2. Cloud Infrastructure Violations');
    
    if (cloudGov.length === 0) {
      core.info('  ℹ️   No custom cloud policies configured.');
    } else {
      cloudGov.forEach(f => {
        if (f.status === 'FAILED') {
          totalFailed += 1;
          core.info(`  ❌  ${f.policy_title || 'Unknown Policy'} (${f.resource})`);
          core.info(`       ↳ Reason: ${f.reason || 'Not compliant'}`);
        } else if (f.status === 'PASSED') {
          core.info(`  ✅  ${f.policy_title || 'Unknown Policy'} (${f.resource})`);
        } else {
          core.info(`  ⚪  ${f.policy_title || 'Unknown Policy'} (Skipped)`);
        }
        blank();
      });
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  3. SUPPLY CHAIN ADVISOR
    // ══════════════════════════════════════════════════════════════════════════
    heading('3. Supply Chain Advisor');
    
    const totalPkg = sbomSummary.total_packages || 0;
    const totalVuln = cveSummary.total || 0;
    const fixableVuln = cveSummary.fixable || 0;

    core.info(`    📦 Packages Scanned       : ${totalPkg}`);
    core.info(`    🛡️ Total Vulnerabilities  : ${totalVuln} (${fixableVuln} fixes available)`);
    
    if (cveCriticals.length > 0) {
      totalFailed += cveCriticals.length; // Count critical CVEs towards the failure limit
      blank();
      core.info(`    🚨 CRITICAL VULNERABILITIES DETECTED:`);
      cveCriticals.forEach(c => {
        core.info(`         🔴 ${c.package}@${c.version}  ->  ${c.id}`);
      });
    } else {
      blank();
      core.info(`    ✅ No CRITICAL vulnerabilities found in the supply chain.`);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  4. SUPPLY CHAIN VIOLATIONS (Custom Supply Chain Policies)
    // ══════════════════════════════════════════════════════════════════════════
    heading('4. Supply Chain Violations');

    if (scGov.length === 0) {
      core.info('  ℹ️   No custom supply chain policies configured.');
    } else {
      scGov.forEach(f => {
        if (f.status === 'FAILED') {
          totalFailed += 1;
          core.info(`  ❌  ${f.policy_title || f.check_id} (${f.resource})`);
          core.info(`       ↳ Cause: ${f.reason}`);
        } else if (f.status === 'PASSED') {
          core.info(`  ✅  ${f.policy_title || f.check_id} (${f.resource})`);
        } else {
          core.info(`  ⚪  ${f.policy_title || f.check_id} (Skipped)`);
        }
        blank();
      });
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  PIPELINE FAIL GATE
    // ══════════════════════════════════════════════════════════════════════════
    blank();
    core.info(L('━'));
    
    // Check if any grouping triggers a fail state
    const shouldFailSec = failedSec.some(f => SEVERITY_ORDER.indexOf(getSeverity(f)) >= SEVERITY_ORDER.indexOf(failOn));
    const shouldFailGov = allGovFindings.some(f => f.status === 'FAILED' && SEVERITY_ORDER.indexOf(getSeverity(f)) >= SEVERITY_ORDER.indexOf(failOn));
    const shouldFailSC = cveCriticals.length > 0 && failOn !== 'none';

    if (failOn !== 'none' && (shouldFailSec || shouldFailGov || shouldFailSC)) {
      core.setFailed(`❌ SecondBoat found violations at or above the ${failOn} severity threshold.`);
    } else if (totalFailed > 0) {
      core.warning(`⚠️ Violations found but they are below the ${failOn} threshold. Pipeline continues.`);
    }

  } catch (err) {
    core.setFailed(`SecondBoat scan failed: ${err.message}`);
  }
}

run();