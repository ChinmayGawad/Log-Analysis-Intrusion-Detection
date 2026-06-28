/* ===================================================================
LogGuard — Log Analysis & Intrusion Detection Engine
=================================================================== */

// ————————————————————————————————————
// 1. DOM REFERENCES
// ————————————————————————————————————
const $ = (sel) => document.querySelector(sel);
const viewUpload = $('#view-upload');
const viewLoading = $('#view-loading');
const viewDashboard = $('#view-dashboard');
const dropZone = $('#drop-zone');
const fileInput = $('#file-input');
const fileInfo = $('#file-info');
const fileName = $('#file-name');
const fileSize = $('#file-size');
const fileRemove = $('#file-remove');
const logInput = $('#log-input');
const btnAnalyze = $('#btn-analyze');
const btnSample = $('#btn-sample');
const btnExport = $('#btn-export');
const btnReset = $('#btn-reset');
const loadingStatus = $('#loading-status');
const filterSeverity = $('#filter-severity');
const filterType = $('#filter-type');
const searchIp = $('#search-ip');
const logTableBody = $('#log-table-body');
const pagination = $('#pagination');
const pageInfo = $('#page-info');
const btnPrev = $('#btn-prev');
const btnNext = $('#btn-next');
const toastContainer = $('#toast-container');

// ————————————————————————————————————
// 2. STATE
// ————————————————————————————————————
let rawLogText = '';
let analysisResults = null;
let filteredResults = [];
let currentPage = 1;
const PAGE_SIZE = 25;
let chartThreats = null;
let chartTimeline = null;

// ————————————————————————————————————
// 3. SAMPLE DATA
// ————————————————————————————————————
const SAMPLE_LOGS = `192.168.1.47 - - [15/Jun/2025:09:12:01 +0000] "GET /admin HTTP/1.1" 403 1234 "-" "Mozilla/5.0"
192.168.1.47 - - [15/Jun/2025:09:12:02 +0000] "GET /admin/login HTTP/1.1" 403 1234 "-" "Mozilla/5.0"
192.168.1.47 - - [15/Jun/2025:09:12:03 +0000] "POST /admin/login HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.47 - - [15/Jun/2025:09:12:04 +0000] "POST /admin/login HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.47 - - [15/Jun/2025:09:12:05 +0000] "POST /admin/login HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.47 - - [15/Jun/2025:09:12:06 +0000] "POST /admin/login HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.47 - - [15/Jun/2025:09:12:07 +0000] "POST /admin/login HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.47 - - [15/Jun/2025:09:12:08 +0000] "POST /admin/login HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.47 - - [15/Jun/2025:09:12:09 +0000] "POST /admin/login HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.47 - - [15/Jun/2025:09:12:10 +0000] "POST /admin/login HTTP/1.1" 401 567 "-" "Mozilla/5.0"
10.0.0.112 - - [15/Jun/2025:09:15:01 +0000] "GET /search?q=1' OR '1'='1 HTTP/1.1" 200 4521 "-" "curl/7.68.0"
10.0.0.112 - - [15/Jun/2025:09:15:03 +0000] "GET /search?q=1'; DROP TABLE users;-- HTTP/1.1" 500 123 "-" "curl/7.68.0"
10.0.0.112 - - [15/Jun/2025:09:15:05 +0000] "POST /login HTTP/1.1" 200 891 "-" "python-requests/2.28.0"
10.0.0.112 - - [15/Jun/2025:09:15:06 +0000] "GET /user?id=1 UNION SELECT * FROM credentials-- HTTP/1.1" 200 3241 "-" "curl/7.68.0"
172.16.0.8 - - [15/Jun/2025:09:20:01 +0000] "GET / HTTP/1.1" 200 321 "-" "Nikto/2.1.6"
172.16.0.8 - - [15/Jun/2025:09:20:01 +0000] "GET /index.html HTTP/1.1" 200 321 "-" "Nikto/2.1.6"
172.16.0.8 - - [15/Jun/2025:09:20:02 +0000] "GET /robots.txt HTTP/1.1" 404 209 "-" "Nikto/2.1.6"
172.16.0.8 - - [15/Jun/2025:09:20:02 +0000] "GET /wp-admin HTTP/1.1" 404 209 "-" "Nikto/2.1.6"
172.16.0.8 - - [15/Jun/2025:09:20:03 +0000] "GET /wp-login.php HTTP/1.1" 404 209 "-" "Nikto/2.1.6"
172.16.0.8 - - [15/Jun/2025:09:20:03 +0000] "GET /phpmyadmin HTTP/1.1" 404 209 "-" "Nikto/2.1.6"
172.16.0.8 - - [15/Jun/2025:09:20:04 +0000] "GET /.env HTTP/1.1" 404 209 "-" "Nikto/2.1.6"
172.16.0.8 - - [15/Jun/2025:09:20:04 +0000] "GET /.git/config HTTP/1.1" 404 209 "-" "Nikto/2.1.6"
172.16.0.8 - - [15/Jun/2025:09:20:05 +0000] "GET /config.php.bak HTTP/1.1" 404 209 "-" "Nikto/2.1.6"
172.16.0.8 - - [15/Jun/2025:09:20:05 +0000] "GET /backup.sql HTTP/1.1" 404 209 "-" "Nikto/2.1.6"
203.0.113.55 - - [15/Jun/2025:09:25:01 +0000] "GET /page/<script>alert('xss')</script> HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
203.0.113.55 - - [15/Jun/2025:09:25:03 +0000] "GET /search?q=<img src=x onerror=alert(1)> HTTP/1.1" 200 892 "-" "Mozilla/5.0"
203.0.113.55 - - [15/Jun/2025:09:25:05 +0000] "POST /comment HTTP/1.1" 200 456 "-" "Mozilla/5.0"
198.51.100.23 - - [15/Jun/2025:09:30:01 +0000] "GET /../../../etc/passwd HTTP/1.1" 400 123 "-" "curl/7.68.0"
198.51.100.23 - - [15/Jun/2025:09:30:02 +0000] "GET /../../../../windows/system32/config/sam HTTP/1.1" 400 123 "-" "curl/7.68.0"
198.51.100.23 - - [15/Jun/2025:09:30:03 +0000] "GET /....//....//etc/shadow HTTP/1.1" 400 123 "-" "curl/7.68.0"
45.33.32.156 - - [15/Jun/2025:09:35:01 +0000] "GET / HTTP/1.1" 200 321 "-" "python-requests/2.28.0"
45.33.32.156 - - [15/Jun/2025:09:35:01 +0000] "GET /api/users HTTP/1.1" 200 4521 "-" "python-requests/2.28.0"
45.33.32.156 - - [15/Jun/2025:09:35:02 +0000] "GET /api/config HTTP/1.1" 403 123 "-" "python-requests/2.28.0"
45.33.32.156 - - [15/Jun/2025:09:35:02 +0000] "GET /api/keys HTTP/1.1" 403 123 "-" "python-requests/2.28.0"
45.33.32.156 - - [15/Jun/2025:09:35:03 +0000] "GET /api/admin HTTP/1.1" 403 123 "-" "python-requests/2.28.0"
45.33.32.156 - - [15/Jun/2025:09:35:03 +0000] "GET /.ssh/id_rsa HTTP/1.1" 403 123 "-" "python-requests/2.28.0"
45.33.32.156 - - [15/Jun/2025:09:35:04 +0000] "GET /api/v1/tokens HTTP/1.1" 403 123 "-" "python-requests/2.28.0"
10.0.0.50 - - [15/Jun/2025:10:01:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
10.0.0.50 - - [15/Jun/2025:10:01:05 +0000] "GET /about.html HTTP/1.1" 200 892 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
10.0.0.51 - - [15/Jun/2025:10:02:10 +0000] "GET /contact HTTP/1.1" 200 567 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X)"
10.0.0.52 - - [15/Jun/2025:10:03:15 +0000] "GET /products HTTP/1.1" 200 2345 "-" "Mozilla/5.0 (X11; Linux x86_64)"
10.0.0.50 - - [15/Jun/2025:10:04:20 +0000] "GET /favicon.ico HTTP/1.1" 404 209 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
10.0.0.53 - - [15/Jun/2025:10:05:00 +0000] "POST /api/login HTTP/1.1" 200 432 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS)"
185.220.101.1 - - [15/Jun/2025:10:10:01 +0000] "GET /shell?cmd=ls HTTP/1.1" 200 892 "-" "curl/7.68.0"
185.220.101.1 - - [15/Jun/2025:10:10:02 +0000] "GET /shell?cmd=cat+/etc/passwd HTTP/1.1" 200 1234 "-" "curl/7.68.0"
185.220.101.1 - - [15/Jun/2025:10:10:03 +0000] "GET /cgi-bin/test?;id HTTP/1.1" 500 123 "-" "curl/7.68.0"
192.168.1.47 - - [15/Jun/2025:10:15:01 +0000] "POST /admin/login HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.47 - - [15/Jun/2025:10:15:02 +0000] "POST /admin/login HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.47 - - [15/Jun/2025:10:15:03 +0000] "POST /admin/login HTTP/1.1" 401 567 "-" "Mozilla/5.0"
10.0.0.112 - - [15/Jun/2025:10:20:01 +0000] "GET /api/user?id=1' AND 1=1-- HTTP/1.1" 200 321 "-" "curl/7.68.0"`;

// ————————————————————————————————————
// 4. DETECTION RULES
// ————————————————————————————————————
const RULES = {
  sql_injection: {
    label: 'SQL Injection',
    severity: 'critical',
    patterns: [
      /('|%27).*?(OR|AND|UNION|SELECT|DROP|INSERT|DELETE|UPDATE|ALTER|CREATE|EXEC|EXECUTE)/i,
      /(UNION\s+SELECT)/i,
      /(DROP\s+TABLE)/i,
      /(OR\s+['"]?\d+['"]?\s*=\s*['"]?\d+)/i,
      /(AND\s+['"]?\d+['"]?\s*=\s*['"]?\d+)/i,
      /(--|;)\s*(SELECT|DROP|DELETE|INSERT|UPDATE|ALTER)/i,
      /(\bEXEC\b|\bEXECUTE\b)/i,
      / INFORMATION_SCHEMA /i,
      / CONCAT\s*\(/i,
      / SLEEP\s*\(/i,
      / BENCHMARK\s*\(/i,
      / WAITFOR\s+DELAY/i,
    ],
  },
  xss: {
    label: 'XSS Attack',
    severity: 'critical',
    patterns: [
      /<script[\s>]/i,
      /on(error|load|click|mouseover|focus|blur)\s*=/i,
      /javascript\s*:/i,
      /<img[^>]+onerror/i,
      /<svg[^>]+onload/i,
      /<iframe[^>]+/i,
      /document\.cookie/i,
      /alert\s*\(/i,
      /eval\s*\(/i,
    ],
  },
  brute_force: {
    label: 'Brute Force',
    severity: 'critical',
    patterns: [], // Detected via frequency analysis
  },
  port_scan: {
    label: 'Port Scan / Recon',
    severity: 'warning',
    patterns: [], // Detected via high 404 rate from single IP
  },
  dir_traversal: {
    label: 'Directory Traversal',
    severity: 'critical',
    patterns: [
      /\.\.[\/\\]/,
      /\.\.%2[fF]/,
      /\.\.%5[cC]/,
      /etc\/passwd/i,
      /etc\/shadow/i,
      /windows\/system32/i,
      /boot\.ini/i,
    ],
  },
  command_injection: {
    label: 'Command Injection',
    severity: 'critical',
    patterns: [
      /[;&|`]\s*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)\b/i,
      /\$\(/i,
      /`[^`]+`/,
      /\/cgi-bin\//i,
      /\bcmd\b\s*=\s*(ls|cat|id|whoami)/i,
    ],
  },
  sensitive_access: {
    label: 'Sensitive File Access',
    severity: 'warning',
    patterns: [
      /\/\.env\b/i,
      /\/\.git\//i,
      /\/\.ssh\//i,
      /\/\.htaccess/i,
      /\/\.htpasswd/i,
      /\/wp-config\.php/i,
      /\/config\.php/i,
      /\/database\.yml/i,
      /\/\.DS_Store/i,
      /\/web\.config/i,
      /\/backup\.(sql|zip|tar|gz)/i,
      /\/dump\.(sql|zip|tar|gz)/i,
      /(\.bak|\.old|\.inc|\.log)\s/i,
    ],
  },
  suspicious_ua: {
    label: 'Suspicious User-Agent',
    severity: 'info',
    patterns: [
      /Nikto/i,
      /sqlmap/i,
      /Nmap/i,
      /Masscan/i,
      /ZmEu/i,
      /DirBuster/i,
      /Gobuster/i,
      /wfuzz/i,
      /Hydra/i,
      /Medusa/i,
      /Wpscan/i,
      /Acunetix/i,
      /Burp\s*Suite/i,
      /MetaSploit/i,
    ],
  },
  auth_bypass: {
    label: 'Auth Bypass Attempt',
    severity: 'critical',
    patterns: [
      /\/admin\/?(\s|$)/i,
      /\/admin\/login/i,
      /\/phpmyadmin/i,
      /\/manager\/html/i,
      /\/console/i,
      /\/actuator/i,
      /\/api\/admin/i,
      /\/api\/keys/i,
      /\/api\/tokens/i,
      /\/api\/config/i,
    ],
  },
};

// ————————————————————————————————————
// 5. LOG PARSER
// ————————————————————————————————————
function parseLogLine(line) {
  const entry = {
    raw: line.trim(),
    ip: null,
    timestamp: null,
    method: null,
    path: null,
    protocol: null,
    status: null,
    size: null,
    userAgent: null,
    threats: [],
  };

  if (!line.trim()) return null;

  // Apache/Nginx Combined Log Format
  const combinedRegex =
    /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s*(\S*)"\s+(\d{3})\s+(\d+|-)\s*"([^"]*)"\s*"([^"]*)"/;
  const match = line.match(combinedRegex);

  if (match) {
    entry.ip = match[1];
    entry.timestamp = match[2];
    entry.method = match[3];
    entry.path = match[4];
    entry.protocol = match[5] || '';
    entry.status = parseInt(match[6]);
    entry.size = match[7] === '-' ? 0 : parseInt(match[7]);
    entry.userAgent = match[9];
    return entry;
  }

  // Generic IP-based format
  const ipRegex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
  const ipMatch = line.match(ipRegex);
  if (ipMatch) {
    entry.ip = ipMatch[1];
    entry.timestamp = null;
    // Try to extract path from quotes
    const pathMatch = line.match(/"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/);
    if (pathMatch) {
      entry.method = pathMatch[1];
      entry.path = pathMatch[2];
    }
    const statusMatch = line.match(/\s(\d{3})\s/);
    if (statusMatch) entry.status = parseInt(statusMatch[1]);
    const uaMatch = line.match(/"([^"]*?)"\s*$/);
    if (uaMatch) entry.userAgent = uaMatch[1];
    return entry;
  }

  // Fallback — treat entire line as raw
  entry.raw = line.trim();
  return entry;
}

function parseAllLogs(text) {
  const lines = text.split('\n');
  const entries = [];
  for (const line of lines) {
    const entry = parseLogLine(line);
    if (entry) entries.push(entry);
  }
  return entries;
}

// ————————————————————————————————————
// 6. INTRUSION DETECTION ENGINE
// ————————————————————————————————————
function detectThreats(entries) {
  const results = [];
  const ipRequestMap = {}; // ip -> [entries]
  const ipFailMap = {}; // ip -> count of 401s
  const ip404Map = {}; // ip -> count of 404s

  // Group by IP
  for (const entry of entries) {
    if (!entry.ip) continue;
    if (!ipRequestMap[entry.ip]) ipRequestMap[entry.ip] = [];
    ipRequestMap[entry.ip].push(entry);
    if (entry.status === 401) ipFailMap[entry.ip] = (ipFailMap[entry.ip] || 0) + 1;
    if (entry.status === 404) ip404Map[entry.ip] = (ip404Map[entry.ip] || 0) + 1;
  }

  // Pattern-based detection
  for (const entry of entries) {
    const checkString = `${entry.method || ''} ${entry.path || ''} ${entry.raw}`;
    const uaString = entry.userAgent || '';

    for (const [ruleKey, rule] of Object.entries(RULES)) {
      if (ruleKey === 'brute_force' || ruleKey === 'port_scan') continue; // Handled separately

      const patterns = ruleKey === 'suspicious_ua' ? rule.patterns : rule.patterns;
      const textToCheck = ruleKey === 'suspicious_ua' ? uaString : checkString;

      for (const pattern of patterns) {
        if (pattern.test(textToCheck)) {
          if (!entry.threats.find(t => t.type === ruleKey)) {
            entry.threats.push({
              type: ruleKey,
              label: rule.label,
              severity: rule.severity,
            });
          }
          break;
        }
      }
    }

    if (entry.threats.length > 0) {
      results.push({ ...entry });
    }
  }

  // Brute Force Detection: 5+ failed auth (401) from same IP
  const BRUTE_FORCE_THRESHOLD = 5;
  for (const [ip, count] of Object.entries(ipFailMap)) {
    if (count >= BRUTE_FORCE_THRESHOLD) {
      const ipEntries = ipRequestMap[ip];
      const latestEntry = ipEntries[ipEntries.length - 1];
      if (!latestEntry.threats.find(t => t.type === 'brute_force')) {
        latestEntry.threats.push({
          type: 'brute_force',
          label: 'Brute Force',
          severity: 'critical',
          meta: `${count} failed attempts`,
        });
        if (!results.find(r => r.raw === latestEntry.raw)) {
          results.push({ ...latestEntry });
        }
      }
    }
  }

  // Port Scan / Recon Detection: 5+ 404s from same IP with scanner-like behavior
  const SCAN_THRESHOLD = 5;
  for (const [ip, count] of Object.entries(ip404Map)) {
    if (count >= SCAN_THRESHOLD) {
      const ipEntries = ipRequestMap[ip];
      const latestEntry = ipEntries[ipEntries.length - 1];
      if (!latestEntry.threats.find(t => t.type === 'port_scan')) {
        latestEntry.threats.push({
          type: 'port_scan',
          label: 'Port Scan / Recon',
          severity: 'warning',
          meta: `${count} 404 responses`,
        });
        if (!results.find(r => r.raw === latestEntry.raw)) {
          results.push({ ...latestEntry });
        }
      }
    }
  }

  return results;
}

// ————————————————————————————————————
// 7. ANALYSIS ORCHESTRATOR
// ————————————————————————————————————
function runAnalysis(text) {
  const startTime = performance.now();

  const entries = parseAllLogs(text);
  const threats = detectThreats(entries);

  // Compute stats
  const uniqueIPs = new Set(entries.filter(e => e.ip).map(e => e.ip));
  const threatIPs = new Set(threats.map(t => t.ip));
  const criticalCount = threats.filter(t => t.threats.some(th => th.severity === 'critical')).length;
  const warningCount = threats.filter(t => t.threats.some(th => th.severity === 'warning')).length;
  const infoCount = threats.filter(t => t.threats.every(th => th.severity === 'info')).length;
  const cleanCount = entries.length - threats.length;
  const cleanPercent = entries.length > 0 ? Math.round((cleanCount / entries.length) * 100) : 100;

  // Threat type distribution
  const threatTypeMap = {};
  for (const t of threats) {
    for (const th of t.threats) {
      threatTypeMap[th.label] = (threatTypeMap[th.label] || 0) + 1;
    }
  }

  // Top threat IPs
  const ipThreatCount = {};
  for (const t of threats) {
    if (t.ip) ipThreatCount[t.ip] = (ipThreatCount[t.ip] || 0) + 1;
  }
  const topIPs = Object.entries(ipThreatCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  // Timeline (group threats by hour or minute)
  const timelineMap = {};
  for (const t of threats) {
    let timeKey = 'Unknown';
    if (t.timestamp) {
      const timeMatch = t.timestamp.match(/(\d{2}:\d{2})/);
      if (timeMatch) timeKey = timeMatch[1];
    }
    timelineMap[timeKey] = (timelineMap[timeKey] || 0) + 1;
  }
  const timeline = Object.entries(timelineMap).sort((a, b) => a[0].localeCompare(b[0]));

  const endTime = performance.now();

  return {
    totalEntries: entries.length,
    allEntries: entries,
    threats,
    uniqueIPs: uniqueIPs.size,
    threatIPs: threatIPs.size,
    criticalCount,
    warningCount,
    infoCount,
    cleanCount,
    cleanPercent,
    threatTypeMap,
    topIPs,
    timeline,
    processingTime: Math.round(endTime - startTime),
  };
}

// ————————————————————————————————————
// 8. VIEW MANAGEMENT
// ————————————————————————————————————
function showView(view) {
  viewUpload.classList.add('hidden');
  viewLoading.classList.add('hidden');
  viewDashboard.classList.add('hidden');
  view.classList.remove('hidden');
  if (view === viewDashboard) view.classList.add('active');
}

// ————————————————————————————————————
// 9. DASHBOARD RENDERING
// ————————————————————————————————————
function renderDashboard(results) {
  analysisResults = results;
  filteredResults = [...results.threats];
  currentPage = 1;

  // Show buttons
  btnExport.classList.add('visible');
  btnReset.classList.add('visible');

  // Summary bar
  $('#summary-total').textContent = `${results.totalEntries.toLocaleString()} entries`;
  $('#summary-critical').textContent = `${results.criticalCount} critical`;
  $('#summary-warning').textContent = `${results.warningCount} warnings`;
  $('#summary-clean').textContent = `${results.cleanCount} clean`;
  $('#summary-time').textContent = `${results.processingTime}ms`;

  // Stat cards
  $('#stat-total').textContent = results.totalEntries.toLocaleString();
  $('#stat-threats').textContent = results.threats.length.toLocaleString();
  $('#stat-ips').textContent = results.uniqueIPs.toLocaleString();
  $('#stat-clean').textContent = `${results.cleanPercent}%`;

  // Populate filter type dropdown
  const types = [...new Set(results.threats.flatMap(t => t.threats.map(th => th.label)))];
  filterType.innerHTML = '<option value="all">All Types</option>';
  for (const type of types.sort()) {
    filterType.innerHTML += `<option value="${type}">${type}</option>`;
  }

  // Render charts
  renderThreatChart(results.threatTypeMap);
  renderTimelineChart(results.timeline);

  // Render threat IPs
  renderThreatIPs(results.topIPs);

  // Render severity bars
  renderSeverityBars(results);

  // Render table
  renderTable();
}

function renderThreatChart(threatTypeMap) {
  const ctx = $('#chart-threats').getContext('2d');
  if (chartThreats) chartThreats.destroy();

  const labels = Object.keys(threatTypeMap);
  const data = Object.values(threatTypeMap);
  const colors = [
    '#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6',
    '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16', '#f43f5e',
  ];

  chartThreats = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors.slice(0, labels.length),
        borderColor: 'rgba(0,0,0,0.8)',
        borderWidth: 2,
        hoverBorderColor: '#fff',
        hoverBorderWidth: 1,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#a3a3a3',
            font: { family: 'Inter', size: 11 },
            padding: 12,
            usePointStyle: true,
            pointStyleWidth: 8,
          },
        },
        tooltip: {
          backgroundColor: 'rgba(23,23,23,0.95)',
          titleColor: '#fff',
          bodyColor: '#a3a3a3',
          borderColor: 'rgba(255,255,255,0.1)',
          borderWidth: 1,
          cornerRadius: 8,
          padding: 12,
          titleFont: { family: 'Inter', weight: '500' },
          bodyFont: { family: 'JetBrains Mono', size: 12 },
        },
      },
    },
  });
}

function renderTimelineChart(timeline) {
  const ctx = $('#chart-timeline').getContext('2d');
  if (chartTimeline) chartTimeline.destroy();

  const labels = timeline.map(t => t[0]);
  const data = timeline.map(t => t[1]);

  chartTimeline = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Threats',
        data,
        borderColor: '#22c55e',
        backgroundColor: 'rgba(34, 197, 94, 0.1)',
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointBackgroundColor: '#22c55e',
        pointBorderColor: '#000',
        pointBorderWidth: 2,
        pointHoverRadius: 6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.03)' },
          ticks: { color: '#525252', font: { family: 'JetBrains Mono', size: 10 } },
        },
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(255,255,255,0.03)' },
          ticks: {
            color: '#525252',
            font: { family: 'JetBrains Mono', size: 10 },
            stepSize: 1,
          },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(23,23,23,0.95)',
          titleColor: '#fff',
          bodyColor: '#a3a3a3',
          borderColor: 'rgba(255,255,255,0.1)',
          borderWidth: 1,
          cornerRadius: 8,
          padding: 12,
          titleFont: { family: 'Inter', weight: '500' },
          bodyFont: { family: 'JetBrains Mono', size: 12 },
        },
      },
    },
  });
}

function renderThreatIPs(topIPs) {
  const container = $('#threat-ips-list');
  if (topIPs.length === 0) {
    container.innerHTML = '<p class="text-sm text-neutral-600">No threats detected.</p>';
    return;
  }

  const maxCount = topIPs[0][1];
  container.innerHTML = topIPs.map(([ip, count], i) => {
    const pct = Math.round((count / maxCount) * 100);
    const severity = count >= 5 ? 'critical' : count >= 3 ? 'warning' : 'info';
    const barColor = severity === 'critical' ? 'bg-red-500' : severity === 'warning' ? 'bg-yellow-500' : 'bg-blue-500';
    return `
      <div class="threat-ip-row flex items-center gap-4 p-3 rounded-lg">
        <span class="text-xs text-neutral-600 w-5 text-right font-[JetBrains_Mono]">${i + 1}</span>
        <span class="ip-copyable text-sm font-[JetBrains_Mono] text-neutral-300 flex-shrink-0 w-36 truncate" data-ip="${ip}" title="${ip}">${ip}</span>
        <div class="flex-1 severity-bar-track">
          <div class="severity-bar-fill ${barColor}" style="width:${pct}%"></div>
        </div>
        <span class="text-xs font-[JetBrains_Mono] text-neutral-400 w-16 text-right">${count} hit${count !== 1 ? 's' : ''}</span>
        <span class="badge badge-${severity}">${severity}</span>
      </div>
    `;
  }).join('');

  // IP copy handlers
  container.querySelectorAll('.ip-copyable').forEach(el => {
    el.addEventListener('click', () => {
      navigator.clipboard.writeText(el.dataset.ip).then(() => {
        showToast('IP copied to clipboard', 'success');
      });
    });
  });
}

function renderSeverityBars(results) {
  const container = $('#severity-bars');
  const total = results.threats.length || 1;
  const items = [
    { label: 'Critical', count: results.criticalCount, color: 'bg-red-500', textColor: 'text-red-400' },
    { label: 'Warning', count: results.warningCount, color: 'bg-yellow-500', textColor: 'text-yellow-400' },
    { label: 'Info', count: results.infoCount, color: 'bg-blue-500', textColor: 'text-blue-400' },
  ];

  container.innerHTML = items.map(item => {
    const pct = Math.round((item.count / total) * 100);
    return `
      <div>
        <div class="flex items-center justify-between mb-1.5">
          <span class="text-xs ${item.textColor} font-medium">${item.label}</span>
          <span class="text-xs font-[JetBrains_Mono] text-neutral-400">${item.count} (${pct}%)</span>
        </div>
        <div class="severity-bar-track">
          <div class="severity-bar-fill ${item.color}" style="width:0%"></div>
        </div>
      </div>
    `;
  }).join('');

  // Animate bars
  requestAnimationFrame(() => {
    const bars = container.querySelectorAll('.severity-bar-fill');
    items.forEach((item, i) => {
      const pct = Math.round((item.count / total) * 100);
      if (bars[i]) bars[i].style.width = `${pct}%`;
    });
  });
}

// ————————————————————————————————————
// 10. TABLE RENDERING + FILTERING
// ————————————————————————————————————
function getFilteredResults() {
  let results = [...analysisResults.threats];
  const sev = filterSeverity.value;
  const type = filterType.value;
  const ip = searchIp.value.trim().toLowerCase();

  if (sev !== 'all') {
    results = results.filter(r => r.threats.some(t => t.severity === sev));
  }
  if (type !== 'all') {
    results = results.filter(r => r.threats.some(t => t.label === type));
  }
  if (ip) {
    results = results.filter(r => r.ip && r.ip.toLowerCase().includes(ip));
  }

  return results;
}

function renderTable() {
  filteredResults = getFilteredResults();
  currentPage = 1;
  renderTablePage();
}

function renderTablePage() {
  const totalPages = Math.max(1, Math.ceil(filteredResults.length / PAGE_SIZE));
  if (currentPage > totalPages) currentPage = totalPages;
  const start = (currentPage - 1) * PAGE_SIZE;
  const pageData = filteredResults.slice(start, start + PAGE_SIZE);

  if (pageData.length === 0) {
    logTableBody.innerHTML = `<tr><td colspan="6" class="px-5 py-10 text-center text-neutral-600">No matching entries found.</td></tr>`;
    pagination.classList.add('hidden');
    return;
  }

  logTableBody.innerHTML = pageData.map((entry, i) => {
    const idx = start + i + 1;
    const primaryThreat = entry.threats[0];
    const allThreatLabels = entry.threats.map(t => t.label).join(', ');
    const sevClass = primaryThreat.severity === 'critical' ? 'badge-critical' : primaryThreat.severity === 'warning' ? 'badge-warning' : 'badge-info';
    const truncatedRaw = entry.raw.length > 120 ? entry.raw.substring(0, 120) + '...' : entry.raw;

    return `
      <tr>
        <td class="text-neutral-600">${idx}</td>
        <td class="text-neutral-300">${entry.ip || '—'}</td>
        <td class="text-neutral-500">${entry.timestamp || '—'}</td>
        <td><span class="threat-badge" title="${allThreatLabels}">${primaryThreat.label}${entry.threats.length > 1 ? ` +${entry.threats.length - 1}` : ''}</span></td>
        <td><span class="badge ${sevClass}">${primaryThreat.severity}</span></td>
        <td class="text-neutral-500" title="${entry.raw.replace(/"/g, '&quot;')}">${truncatedRaw}</td>
      </tr>
    `;
  }).join('');

  // Pagination
  pagination.classList.remove('hidden');
  pageInfo.textContent = `Showing ${start + 1}–${Math.min(start + PAGE_SIZE, filteredResults.length)} of ${filteredResults.length}`;
  btnPrev.disabled = currentPage <= 1; 
  btnNext.disabled = currentPage >= totalPages;
}

// ————————————————————————————————————
// 11. EXPORT REPORT
// ————————————————————————————————————
function exportReport() {
  if (!analysisResults) return;
  const r = analysisResults;

  let threatRows = r.threats.map((t, i) => {
    const th = t.threats.map(th => `${th.label} (${th.severity})`).join(', ');
    return `<tr>
          <td style="padding:8px 12px;border-bottom:1px solid #222;color:#888;font-size:12px;">${i + 1}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #222;color:#d4d4d4;font-size:12px;font-family:monospace;">${t.ip || '—'}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #222;color:#888;font-size:12px;">${t.timestamp || '—'}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #222;color:#d4d4d4;font-size:12px;">${th}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #222;color:#888;font-size:11px;font-family:monospace;max-width:500px;word-break:break-all;">
            ${t.raw.replace(/</g, '&lt;').replace(/>/g, '&gt;')}
          </td>
        </tr>`;
  }).join('');

  const topIPRows = r.topIPs.map(([ip, count]) => {
    return `<tr>
          <td style="padding:6px 12px;border-bottom:1px solid #222;color:#d4d4d4;font-size:12px;font-family:monospace;">${ip}</td>
          <td style="padding:6px 12px;border-bottom:1px solid #222;color:#ef4444;font-size:12px;font-family:monospace;">${count}</td>
        </tr>`;
  }).join('');

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>LogGuard Report</title>
  <style>
    body {
      background: #0a0a0a;
      color: #fff;
      font-family: Inter, system-ui, sans-serif;
      padding: 40px;
      max-width: 1000px;
      margin: 0 auto;
    }
    h1 {
      font-size: 28px;
      margin-bottom: 4px;
    }
    h2 {
      font-size: 18px;
      margin: 40px 0 16px;
      color: #a3a3a3;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin: 24px 0;
    }
    .stat {
      background: #111;
      border: 1px solid #222;
      border-radius: 12px;
      padding: 20px;
    }
    .stat .num {
      font-size: 32px;
      font-weight: 600;
      font-family: monospace;
    }
    .stat .lbl {
      font-size: 12px;
      color: #666;
      margin-top: 4px;
    }
    .red { color: #ef4444; }
    .yellow { color: #eab308; }
    .green { color: #22c55e; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
    }
    th {
      text-align: left;
      padding: 8px 12px;
      color: #525252;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid #222;
    }
    .footer {
      margin-top: 60px;
      text-align: center;
      color: #333;
      font-size: 12px;
    }
  </style>
</head>
<body>
  <h1>🛡️ LogGuard Report</h1>
  <p style="color:#666;margin-bottom:0;">Generated: ${new Date().toISOString()} · Processing time: ${r.processingTime}ms</p>
  <div class="stats">
    <div class="stat">
      <div class="num">${r.totalEntries}</div>
      <div class="lbl">Total Entries</div>
    </div>
    <div class="stat">
      <div class="num red">${r.threats.length}</div>
      <div class="lbl">Threats Found</div>
    </div>
    <div class="stat">
      <div class="num yellow">${r.uniqueIPs}</div>
      <div class="lbl">Unique IPs</div>
    </div>
    <div class="stat">
      <div class="num green">${r.cleanPercent}%</div>
      <div class="lbl">Clean Traffic</div>
    </div>
  </div>
  <h2>Top Threat IPs</h2>
  <table>
    <thead>
      <tr>
        <th>IP Address</th>
        <th>Threat Count</th>
      </tr>
    </thead>
    <tbody>${topIPRows}</tbody>
  </table>
  <h2>Flagged Entries (${r.threats.length})</h2>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>IP</th>
        <th>Timestamp</th>
        <th>Threats</th>
        <th>Log Entry</th>
      </tr>
    </thead>
    <tbody>${threatRows}</tbody>
  </table>
  <div class="footer">LogGuard — Log Analysis & Intrusion Detection · chinmaygawad</div>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `logguard-report-${Date.now()}.html`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Report downloaded successfully', 'success');
}

// ————————————————————————————————————
// 12. TOAST SYSTEM
// ————————————————————————————————————
function showToast(message, type = 'info') {
  const colors = {
    success: 'border-green-500/30 bg-green-500/10 text-green-400',
    error: 'border-red-500/30 bg-red-500/10 text-red-400',
    info: 'border-blue-500/30 bg-blue-500/10 text-blue-400',
    warning: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400',
  };
  const icons = {
    success: 'check-circle',
    error: 'x-circle',
    info: 'info',
    warning: 'alert-triangle',
  };

  const toast = document.createElement('div');
  toast.className = `toast flex items-center gap-3 px-5 py-3 rounded-xl border ${colors[type]} text-sm`;
  toast.style.backdropFilter = 'blur(12px)';
  toast.innerHTML = `<i data-lucide="${icons[type]}" class="w-4 h-4 flex-shrink-0"></i><span>${message}</span>`;
  toastContainer.appendChild(toast);
  lucide.createIcons({ nodes: [toast] });

  setTimeout(() => {
    toast.classList.add('removing');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ————————————————————————————————————
// 13. EVENT HANDLERS
// ————————————————————————————————————

// File drop zone
['dragenter', 'dragover'].forEach(evt => {
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
});

['dragleave', 'drop'].forEach(evt => {
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
  });
});

dropZone.addEventListener('drop', (e) => {
  const file = e.dataTransfer.files[0];
  if (file) handleFile(file);
});

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) handleFile(fileInput.files[0]);
});

function handleFile(file) {
  if (file.size > 50 * 1024 * 1024) {
    showToast('File too large. Maximum 50MB allowed.', 'error');
    return;
  }
  rawLogText = '';
  logInput.value = '';
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);
  fileInfo.classList.remove('hidden');
  dropZone.classList.add('has-file');

  const reader = new FileReader();
  reader.onload = (e) => {
    rawLogText = e.target.result;
    updateAnalyzeButton();
  };
  reader.readAsText(file);
}

fileRemove.addEventListener('click', () => {
  rawLogText = '';
  fileInput.value = '';
  fileInfo.classList.add('hidden');
  dropZone.classList.remove('has-file');
  updateAnalyzeButton();
});

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Textarea input
logInput.addEventListener('input', () => {
  rawLogText = logInput.value;
  if (rawLogText.trim()) {
    rawLogText = '';
    fileInput.value = '';
    fileInfo.classList.add('hidden');
    dropZone.classList.remove('has-file');
  }
  updateAnalyzeButton();
});

function updateAnalyzeButton() {
  const hasContent = (rawLogText && rawLogText.trim().length > 0) || (logInput.value.trim().length > 0);
  btnAnalyze.disabled = !hasContent;
}

// Sample data
btnSample.addEventListener('click', () => {
  logInput.value = SAMPLE_LOGS;
  rawLogText = '';
  fileInput.value = '';
  fileInfo.classList.add('hidden');
  dropZone.classList.remove('has-file');
  updateAnalyzeButton();
  showToast('Sample intrusion logs loaded', 'info');
});

// Analyze button
btnAnalyze.addEventListener('click', async () => {
  const text = rawLogText || logInput.value;
  if (!text.trim()) return;

  showView(viewLoading);

  // Simulate processing stages
  const stages = [
    'Parsing log entries...',
    'Extracting IP addresses and timestamps...',
    'Running pattern detection rules...',
    'Analyzing frequency-based anomalies...',
    'Classifying threat severity...',
    'Generating report...',
  ];

  for (let i = 0; i < stages.length; i++) {
    loadingStatus.textContent = stages[i];
    await sleep(250 + Math.random() * 200);
  }
  const results = runAnalysis(text);
  renderDashboard(results);
  showView(viewDashboard);
  showToast(`Analysis complete: ${results.threats.length} threats detected`, results.threats.length > 0 ? 'warning' : 'success');
});

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Filters
filterSeverity.addEventListener('change', renderTable);
filterType.addEventListener('change', renderTable);
searchIp.addEventListener('input', () => {
  currentPage = 1;
  renderTablePage();
  // Re-filter on full input
  clearTimeout(searchIp._debounce);
  searchIp._debounce = setTimeout(renderTable, 300);
});

// Pagination
btnPrev.addEventListener('click', () => {
  if (currentPage > 1) { currentPage--; renderTablePage(); }
});

btnNext.addEventListener('click', () => {
  const totalPages = Math.ceil(filteredResults.length / PAGE_SIZE);
  if (currentPage < totalPages) { currentPage++; renderTablePage(); }
});

// Export
btnExport.addEventListener('click', exportReport);

// Reset
btnReset.addEventListener('click', () => {
  rawLogText = '';
  logInput.value = '';
  fileInput.value = '';
  fileInfo.classList.add('hidden');
  dropZone.classList.remove('has-file');
  analysisResults = null;
  filteredResults = [];
  currentPage = 1;
  if (chartThreats) { chartThreats.destroy(); chartThreats = null; }
  if (chartTimeline) { chartTimeline.destroy(); chartTimeline = null; }
  btnExport.classList.remove('visible');
  btnReset.classList.remove('visible');
  filterSeverity.value = 'all';
  filterType.innerHTML = '<option value="all">All Types</option>';
  searchIp.value = '';
  updateAnalyzeButton();
  showView(viewUpload);
  showToast('Reset complete', 'info');
});

// ————————————————————————————————————
// 14. INIT
// ————————————————————————————————————
lucide.createIcons();
updateAnalyzeButton();