# Methodology: a reusable 3-step SSRF probe for user-supplied URL parameters

This is the playbook I now apply to any target that accepts user-supplied URLs
in a webhook, callback, status-URL, fallback-URL, or integration field. It is
the methodology that surfaced the finding written up in [`report.md`](./report.md).

The methodology generalizes deliberately. The *target* in the case study
happened to be a webhook URL on a SaaS communications API, but every step
applies unchanged to any product surface where a server fetches a URL the
user controlled.

---

## Why this surface

Modern SaaS products lean heavily on user-supplied URLs:

- **Webhooks**: "POST to this URL when X happens"
- **Callbacks / status URLs**: "tell my server when the job finishes"
- **Fallback URLs**: "if the primary URL fails, try this one"
- **Integration endpoints**: "fetch the user's data from here"

Every one of these is a server-side HTTP client controlled by user input. If
the input isn't strictly validated *and* the fetcher doesn't re-validate after
redirects, the surface is a candidate for SSRF. I went looking for exactly
that pattern.

---

## Step 1: URL acceptance check

Submit an internal address directly as the URL parameter:

```
<url_param>=http://169.254.169.254/latest/meta-data/
```

If the server returns 200 OK and persists the value, there is **no
registration-time validation**. That alone isn't exploitable, but it tells
you the validation layer (if any) lives at fetch time, not at write time.
That's a load-bearing observation for Step 3.

---

## Step 2: Out-of-band (OOB) confirmation

Replace the URL with a listener you control (e.g. webhook.site). Trigger the
feature that causes the server to fetch the URL: make the call, send the
message, fire the event.

If you receive an inbound HTTP request on your listener, the server is
fetching URLs server-side. Run reverse DNS on the source IP:

```bash
dig +tcp -x <source_ip>
```

If it resolves to the target's infrastructure (e.g. an EC2 PTR in their
production region), you've confirmed two things:

1. The fetch is server-side, not browser-side
2. The fetcher is inside their cloud network, i.e. close enough to IMDS to
   potentially reach it

That's the prerequisite for IMDS-class SSRF. Without OOB confirmation you
don't actually know whether the server is fetching server-side or
client-side, and the difference is the entire bug.

---

## Step 3: Redirect-chain bypass

Even if direct internal IPs are blocked at the URL field, the bypass is
almost always the same: validate the *initial* URL, but follow redirects
without re-validating.

Deploy a tiny redirect server (Flask on a free PaaS host works fine):

```python
from flask import Flask, redirect

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def redir():
    return redirect("http://169.254.169.254/latest/meta-data/", code=301)

if __name__ == "__main__":
    app.run()
```

Register *that* URL as the webhook. Trigger the feature. Check your redirect
server's access logs.

If you see the target's outbound proxy hitting your endpoint and receiving
the 301, the fetcher followed the redirect toward `169.254.169.254`. A 502
from the fetcher afterward still counts: it means the request was attempted;
the metadata response just didn't make it back through the network path.
That's classified as **Blind SSRF**: outbound request confirmed, response not
retrieved.

### Why this works

The validation logic almost always runs at write time, against the URL the
user submits. The redirect happens at fetch time, after that check has
already passed. Two separate codepaths, two separate trust boundaries, and
the second one usually doesn't exist.

---

## What I did *not* do

Active exploitation of the metadata endpoint (i.e. actually retrieving IAM
credentials) was deliberately avoided. The bypass was demonstrated up to
the point of the outbound request leaving the target's proxy. Anything past
that line crosses from "proof of vulnerability" into "exploitation of
internal infrastructure," which is out of scope on essentially every
bug-bounty program and unnecessary to prove the bug exists.

This is a deliberate methodology choice, not a limitation. **Confirm the
primitive; do not exfiltrate.**

---

## Lessons / takeaways

1. **Webhook URL parameters are a high-yield SSRF surface.** Any field whose
   name ends in `Url`, `Callback`, `Webhook`, or `Endpoint` deserves the
   three-step probe.
2. **Registration-time validation is not fetch-time validation.** A target
   can correctly reject `http://169.254.169.254` at write time and still
   follow a 301 to it at fetch time. These are two different controls and
   they have to be implemented separately.
3. **OOB confirmation is non-negotiable.** Without an inbound request to a
   listener you control, you don't actually know whether the server is
   fetching server-side or client-side, and the difference is the entire
   bug.
4. **Reverse DNS the source IP.** It's free, it takes one command, and it's
   the difference between "some box on the internet fetched my URL" and "an
   instance inside the target's production cloud account fetched my URL."
   Only the second one matters for IMDS-class SSRF.
5. **Stop at the primitive.** Outbound-request-confirmed is a complete
   report. Credential exfiltration is not your job.

---

## Vulnerability class references

- **CWE-918**: Server-Side Request Forgery
- **OWASP**: SSRF (A10:2021)
- **AWS IMDSv1**: `http://169.254.169.254/latest/meta-data/` (the canonical
  SSRF target inside AWS; mitigated by IMDSv2's session-token requirement,
  which is why providers should enforce IMDSv2 on every instance that
  fetches user-supplied URLs)

See also: [`checklist.md`](./checklist.md), the one-page operator version of
this methodology.
