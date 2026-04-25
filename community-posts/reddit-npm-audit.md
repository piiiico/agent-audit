# Reddit Distribution: npm Audit Article

**Article URL:** https://dev.to/piiiico/i-audited-every-npm-package-with-10m-weekly-downloads-here-is-the-risk-map-16k0
**Published:** 2026-04-17
**Status:** DRAFT — needs Reddit credentials to post

---

## r/javascript

**Title:** I audited all 41 npm packages with >10M weekly downloads. 16 have a single maintainer — covering 2.82B downloads/week.

**Type:** Link post → dev.to article URL

**Why it works:** Data-first, no hype. The numbers are real and verifiable. r/javascript audience cares about supply chain health.

---

## r/node

**Title:** Single-maintainer risk audit: 16 of 41 npm packages with >10M weekly downloads have only 1 maintainer (2.82B downloads/week)

**Type:** Link post → dev.to article URL

**Key data to include in comment:**
- minimatch: 560M/wk, 1 maintainer
- chalk: 413M/wk, 1 maintainer
- glob: 332M/wk, 1 maintainer
- postcss: 206M/wk, 1 maintainer
- esbuild: 190M/wk, 1 maintainer
- zod: 158M/wk, 1 maintainer
- Total at risk: 2.82B downloads/week

**Soft CTA:** Article naturally links to getcommit.dev/watchlist for monitoring

---

## Notes for Posting

- Post r/javascript first, then r/node after 24h
- Do NOT cross-post simultaneously (spam filter)
- Post on weekday morning Oslo/Europe time for best engagement
- Account posting: piiiico or hawkaa (need Reddit credentials)
- **Requires:** REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET, REDDIT_USERNAME, REDDIT_PASSWORD in /workspace/.secrets/reddit.env

---

## Reddit OAuth Script Needed

The existing /workspace/bin/reddit-fetch.ts handles reading. Need to create a submit script at /workspace/bin/reddit-submit.ts using OAuth "password" grant type:
- Endpoint: POST https://www.reddit.com/r/{subreddit}/submit
- Auth: username/password OAuth with script app credentials
- Fields: kind=link, title, url, nsfw=false, spoiler=false
