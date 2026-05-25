# Blind SSRF via Open-Redirect Chain in a Webhook URL Parameter

> Bug-bounty case study against a large SaaS communications provider.
> Vendor, product, account, and infrastructure-specific details have been
> removed. The methodology and reasoning are preserved verbatim.

## What this repo is

A writeup of a real Server-Side Request Forgery finding I worked on a public
bug-bounty program. It exists to show *how I approached the target*, not just
the result. The repo is structured so a reviewer can read in any order:

| File | Purpose |
|---|---|
| [`methodology.md`](./methodology.md) | The reusable 3-step probe I now apply to any user-supplied URL parameter. Lead with this. |
| [`report.md`](./report.md) | The vulnerability report itself: endpoint, repro steps, impact, remediation, recon context. Anonymized. |
| [`checklist.md`](./checklist.md) | One-page operator checklist derived from the methodology. |
| `README.md` | This file. TL;DR + framing + the case for systematic methodology. |

## TL;DR

A webhook-style feature in the target's public API accepted arbitrary URLs
from authenticated users and fetched them server-side at event time. Direct
internal addresses were stored without validation, and the server's outbound
proxy followed HTTP 301 redirects without re-validating the destination,
producing a confirmed **Blind SSRF** with a clear path toward the AWS Instance
Metadata Service (IMDS) at `169.254.169.254`.

Outbound request from the target's proxy was confirmed in my redirector's
access logs. Active exploitation of the metadata endpoint was deliberately
avoided. See [§ What I did not do](./methodology.md#what-i-did-not-do).

## Why I'm publishing this

Recruiters and hiring managers reading bug-bounty portfolios get a lot of
"I found X" posts. This one is structured to answer the question they're
actually asking:

> *Does this person have a repeatable methodology, or did they get lucky once?*

The finding is one paragraph. The methodology is the rest of the repo, and
it's the part that generalizes to the next target.

## How I got here

The SSRF wasn't the first thing I tried. It was the surviving lead after
working through a few hundred subdomains: an unauthenticated admin SPA
(every API call gated by SSO), a stale staging host (500s on every path),
a token-gated staging service (401 without a token), several
"decommissioned" CNAMEs (target still owned the underlying CDN
distributions), and a full IDOR pass across two attacker-owned accounts on
five endpoint variants (all 401).

The full breakdown of what got ruled out and why is in
[`report.md` § Recon context](./report.md#recon-context). The short version:
**most of the surface was well-secured.** The SSRF existed not because the
platform was sloppy, but because URL validation in webhook parameters is a
specific, easy-to-overlook class, and the redirect bypass is a specific,
easy-to-overlook follow-up.

That's the case for systematic methodology over opportunistic poking: the
bug was where the methodology said it would be, not where the code looked
weakest.

## Skills demonstrated

- **Recon at scale**: subdomain enumeration, live-host detection, header
  fingerprinting across several hundred hosts; triage of what's worth manual
  investigation vs. what to drop. The negative results in
  [`report.md`](./report.md#recon-context) matter as much as the positive one.
- **SSRF class knowledge**: registration-time vs. fetch-time validation,
  open-redirect chains, IMDS targeting, OOB confirmation via listener +
  reverse DNS to confirm the request originated from inside the target's
  cloud network.
- **Disciplined scope**: stopping at the primitive. Outbound-request-
  confirmed is a complete bug bounty report; credential exfiltration is not
  my job and is out of scope on essentially every program.
- **Writeup quality**: separate audiences. The report is for the security
  team that has to triage and fix; the methodology is for the next person
  (including me) who has to apply the same playbook on a different target.

## Evidence

### OOB confirmation — inbound request to webhook listener

![Webhook.site capture showing inbound POST from target EC2 IP](./images/image-1(scrubbed).png)
*Webhook.site capture: inbound POST from target EC2 IP (`<redacted>`), confirming server-side fetch.*

### Reverse DNS — request originated inside AWS

![dig PTR lookup confirming EC2 reverse DNS](./images/image-2(scrubbed).png)
*`dig` PTR lookup: resolves to `ec2-<redacted>.compute-1.amazonaws.com`, placing the fetcher inside the target's production cloud network — a prerequisite for IMDS-class SSRF.*

### Redirect chain — 301 followed toward IMDS

![Redirector access logs showing 301 served to target proxy](./images/image-3(scrubbed).png)
*Redirector access logs: target proxy received the 301 toward `169.254.169.254` without re-validation — outbound request confirmed, finding complete.*

---

## The reusable bit

If you only read one file, read [`methodology.md`](./methodology.md). The
three steps (*URL acceptance check → OOB confirmation → redirect-chain
bypass*) apply to any product surface that accepts user-supplied URLs:
webhooks, callbacks, status URLs, fallback URLs, integrations.

## Contact

This repo is part of my security portfolio. For program coordinators,
recruiters, or anyone with a question about the methodology: open an issue or
reach out via the contact link on my GitHub profile.
