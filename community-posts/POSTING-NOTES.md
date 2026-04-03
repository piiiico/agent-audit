# Posting Notes

## Timing
- **Best window:** Tuesday-Thursday, 9-11am EST (15:00-17:00 CET)
- Post HN first, then Reddit 1-2 hours later (avoids looking like spam)

## Order
1. **Show HN** — submit URL (github.com/piiiico/agent-audit), then immediately post the comment text
2. **r/mcp** — MCP-specific angle, practical focus
3. **r/netsec** — research/findings-first, tool is secondary

## Numbers (updated Apr 1, 2026)
All drafts now match FINDINGS.md curated numbers: 12 repos, 22 critical, 13 high, 17 hardcoded creds (prod only), 0 SSL issues in production. The "29 child_process imports" figure is confirmed accurate from scan-results.json.

## Pre-flight checklist
- [ ] Package name: currently `@piiiico/agent-audit` (scoped). Consider publishing unscoped `agent-audit` for cleaner npx command. Not blocking — scoped works fine.
- [ ] No demo GIF in README yet. Consider adding one before posting — HN/Reddit posts with visual demos get more traction. A simple asciinema recording of `npx @piiiico/agent-audit --auto` would work.
- [ ] Make sure GitHub repo is public and README renders correctly
- [ ] Verify `npx @piiiico/agent-audit --auto` works cleanly on a fresh machine

## Engagement strategy
- Reply to every substantive comment in the first 2 hours (critical for HN ranking)
- For "false positive" complaints: acknowledge, open an issue, thank them
- For "just use X instead": explain what's MCP-specific vs generic SAST
- Don't be defensive about the findings count — let the methodology speak
