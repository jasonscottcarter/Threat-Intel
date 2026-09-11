require('dotenv').config();
const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const VT_KEY = process.env.VT_API_KEY;
const URLSCAN_KEY = process.env.URLSCAN_API_KEY;
const IPINFO_TOKEN = process.env.IPINFO_TOKEN;

// Auto-detect indicator type
function detectType(indicator) {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
  const urlRegex = /^https?:\/\/.+/;
  if (ipRegex.test(indicator)) return 'ip';
  if (hashRegex.test(indicator)) return 'hash';
  if (urlRegex.test(indicator)) return 'url';
  return 'domain';
}

// VirusTotal — handles all indicator types
async function queryVirusTotal(indicator, type) {
  try {
    let endpoint;
    if (type === 'ip') endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${indicator}`;
    else if (type === 'domain') endpoint = `https://www.virustotal.com/api/v3/domains/${indicator}`;
    else if (type === 'hash') endpoint = `https://www.virustotal.com/api/v3/files/${indicator}`;
    else {
      const urlId = Buffer.from(indicator).toString('base64').replace(/=/g, '');
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    }
    const res = await axios.get(endpoint, { headers: { 'x-apikey': VT_KEY } });
    const attr = res.data.data.attributes;
    const stats = attr.last_analysis_stats || {};
    return {
      source: 'VirusTotal',
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      clean: stats.undetected || 0,
      total: Object.values(stats).reduce((a, b) => a + b, 0),
      reputation: attr.reputation,
      country: attr.country,
      asOwner: attr.as_owner,
      lastAnalysis: attr.last_analysis_date
        ? new Date(attr.last_analysis_date * 1000).toLocaleString() : 'N/A'
    };
  } catch (err) {
    return { source: 'VirusTotal', error: err.response?.data?.error?.message || err.message };
  }
}

// IPinfo — IPs only
async function queryIPInfo(ip) {
  try {
    const res = await axios.get(`https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}`);
    const d = res.data;
    return {
      source: 'IPinfo',
      ip: d.ip, hostname: d.hostname, city: d.city,
      region: d.region, country: d.country, org: d.org,
      loc: d.loc, timezone: d.timezone
    };
  } catch (err) {
    return { source: 'IPinfo', error: err.response?.data?.message || err.message };
  }
}

// URLscan.io — domains and URLs
async function queryURLScan(indicator, type) {
  try {
    const query = type === 'url' ? `page.url:"${indicator}"` : `domain:${indicator}`;
    const res = await axios.get(
      `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}&size=5`,
      { headers: { 'API-Key': URLSCAN_KEY } }
    );
    const results = res.data.results || [];
    if (!results.length) return { source: 'URLscan.io', message: 'No prior scans found' };
    const latest = results[0];
    return {
      source: 'URLscan.io',
      totalScans: results.length,
      latestScan: latest.task?.time,
      verdict: latest.verdicts?.overall?.malicious ? 'Malicious' : 'Clean',
      score: latest.verdicts?.overall?.score,
      resultURL: `https://urlscan.io/result/${latest.task?.uuid}/`
    };
  } catch (err) {
    return { source: 'URLscan.io', error: err.response?.data?.message || err.message };
  }
}

// Main lookup route
app.post('/lookup', async (req, res) => {
  const { indicator } = req.body;
  if (!indicator) return res.status(400).json({ error: 'No indicator provided' });
  const type = detectType(indicator.trim());
  const promises = [queryVirusTotal(indicator.trim(), type)];
  if (type === 'ip') promises.push(queryIPInfo(indicator.trim()));
  if (type === 'domain' || type === 'url') promises.push(queryURLScan(indicator.trim(), type));
  const sources = await Promise.all(promises);
  res.json({ type, indicator, sources });
});

app.listen(3000, () => console.log('Threat Intel Dashboard running at http://localhost:3000'));