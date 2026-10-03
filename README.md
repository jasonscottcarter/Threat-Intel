# Threat Intel Dashboard

A local Node.js web app that looks up IPs, domains, URLs, and file hashes across VirusTotal, URLscan.io, and IPinfo from a single search box.

<!-- Add a screenshot made from a harmless indicator, e.g.: ![Dashboard](docs/screenshot.png) -->

## Features

- Auto-detects the indicator type (IPv4, domain, URL, or MD5/SHA-1/SHA-256 hash) and queries the relevant sources in parallel
- **VirusTotal:** detection counts, reputation score, country, AS owner, and last analysis time
- **IPinfo:** geolocation, ASN and organization, hostname, and timezone (IPs only)
- **URLscan.io:** verdict and risk score from prior scans, with a link to the full report (domains and URLs)
- Dark-themed single-page dashboard served locally by Express
- API keys stay in a local `.env` file and are never sent to the browser

## Which sources answer which lookups

| Indicator | Sources queried |
| --- | --- |
| IP address | VirusTotal, IPinfo |
| Domain | VirusTotal, URLscan.io |
| URL | VirusTotal, URLscan.io |
| File hash | VirusTotal |

Lookups read existing reports only. URLscan.io is searched for prior scans, and nothing is submitted for scanning.

## Prerequisites

- [Node.js](https://nodejs.org) (LTS version). Verify with `node --version`
- [Git](https://git-scm.com). Verify with `git --version`
- A code editor such as [VS Code](https://code.visualstudio.com) (optional)

## API keys

You need a free account and API key for each service:

| Service | Sign up | Where to find your key |
| --- | --- | --- |
| VirusTotal | [virustotal.com](https://www.virustotal.com) | Profile avatar, then API key |
| URLscan.io | [urlscan.io](https://urlscan.io) | Username, then Settings, then API Key |
| IPinfo | [ipinfo.io](https://ipinfo.io) | Home dashboard (token shown on login) |

## Installation

```bash
git clone https://github.com/jasonscottcarter/threat-intel.git
cd threat-intel
npm install
```

Create a file named `.env` (no extension) in the project root:

```
VT_API_KEY=your_virustotal_key_here
URLSCAN_API_KEY=your_urlscan_key_here
IPINFO_TOKEN=your_ipinfo_token_here
```

`.env` is excluded from the repository by `.gitignore`. You must create it on every machine you run the app on, and never commit it.

## Running

```bash
node server.js
```

You should see `Threat Intel Dashboard running at http://localhost:3000`. Open that address in your browser. Press `Ctrl+C` in the terminal to stop the server.

## Usage

Paste an IP, domain, URL, or file hash into the search box and click **Lookup** (or press Enter). A badge shows the detected type, and one result card appears per source. If a source fails, its card shows the error and the other sources still display.

Examples: `8.8.8.8`, `example.com`, `https://example.com/path`, or a file hash.

## Project structure

```
threat-intel/
├── public/
│   └── index.html     # Frontend dashboard
├── .gitignore
├── package.json
├── package-lock.json
└── server.js          # Express backend and API integrations
```

## Security notes

- **Run it locally only.** The server has no authentication and listens on port 3000. Use it on a trusted machine and network, and don't expose the port to the internet.
- **Indicators leave your machine.** Anything you enter is sent to VirusTotal, URLscan.io, or IPinfo, depending on type. Don't look up sensitive or internal indicators you wouldn't want a third party to see.
- **Keep your keys private.** Never commit `.env`. If a key is ever exposed, rotate it in that service's account settings.

## Limitations

- VirusTotal's free tier is rate-limited (about 4 requests per minute at the time of writing), so rapid lookups may return errors.
- Auto-detection recognizes IPv4 only. IPv6 addresses are treated as domains.
- A "Clean" verdict means a source has no detections, not that an indicator is safe.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `node: command not found` | Node.js isn't installed or isn't on your PATH. Reinstall it and open a new terminal. |
| `Cannot find module 'express'` | Run `npm install` from inside the `threat-intel` folder. |
| Port 3000 already in use | Change `3000` to another port at the bottom of `server.js`, restart, and use that port in the browser. |
| A card shows an authentication or "invalid key" error | Check the matching value in `.env`, then restart the server. |
| A card shows a quota or rate-limit error | Wait a minute and retry, or check your plan limits with that service. |

## Built with

Node.js, Express, Axios, dotenv, and vanilla JavaScript.

## License

MIT. See `LICENSE`.
