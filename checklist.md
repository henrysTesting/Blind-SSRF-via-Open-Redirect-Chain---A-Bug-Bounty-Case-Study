# Operator Checklist: SSRF Probe for User-Supplied URL Parameters

One-page version of [`methodology.md`](./methodology.md). For any target with
a user-supplied URL field (webhook, callback, status URL, fallback URL,
integration endpoint):

## Pre-flight

- [ ] Identify every URL-shaped field on the target's API. Anything ending in
      `Url`, `Callback`, `Webhook`, or `Endpoint` is a candidate.
- [ ] Confirm the field is fetched server-side at event time (not just
      stored). Read the docs first; the API often tells you.
- [ ] Have a low-cost authenticated account on the target.

## Step 1: Registration-time validation check

- [ ] Submit `http://169.254.169.254/latest/meta-data/` directly as the URL
      value.
- [ ] Does the API return 200 OK and persist it?
  - Yes → no registration-time validation. Continue.
  - No → note the rejection mode (regex? DNS resolution? IP-range check?).
        Move to Step 3; redirect bypass may still work.

## Step 2: Out-of-band fetch confirmation

- [ ] Replace the URL with a webhook listener you control (webhook.site,
      interactsh, your own).
- [ ] Fire the event that causes the server to fetch the URL.
- [ ] Inbound request arrived on your listener?
  - Yes → server-side fetch confirmed.
  - No → either the fetch is client-side, the event didn't fire, or
        outbound is blocked. Stop and re-examine the feature.
- [ ] Reverse-DNS the source IP: `dig +tcp -x <source_ip>`
- [ ] Does the PTR resolve to the target's cloud infrastructure (EC2 in
      their production region, etc.)?
  - Yes → fetcher is inside their cloud network. IMDS is in reach.
  - No → still SSRF-capable in principle, but IMDS is not the right
        target. Reassess the impact story.

## Step 3: Redirect-chain bypass

- [ ] Stand up a tiny redirector. Flask on a free PaaS host is enough:

  ```python
  from flask import Flask, redirect

  app = Flask(__name__)

  @app.route("/", methods=["GET", "POST"])
  def redir():
      return redirect("http://169.254.169.254/latest/meta-data/", code=301)
  ```

- [ ] Register the redirector URL as the webhook value.
- [ ] Fire the event.
- [ ] Check the redirector's access logs.
  - Saw the target's proxy User-Agent and a 301 response → redirect was
    issued; the fetcher will (or did) follow it.
  - Got a 502 from the event runtime after the redirect → outbound request
    was attempted but the response didn't return through the network path.
    **Still counts as Blind SSRF.**

## Documentation for the report

Capture before you write up:

- [ ] Exact endpoint, parameter name, request body for registration.
- [ ] Source IP of the OOB request + reverse-DNS output.
- [ ] Redirector log line showing the proxy User-Agent and the 301.
- [ ] HTTP status returned by the fetcher after the redirect (502 is fine).
- [ ] List of sibling URL fields on the same resource (likely all share the
      validation path).

## Stop here

- [ ] **Do not** trigger another fetch with the metadata URL directly to
      see what comes back.
- [ ] **Do not** use the redirector to chain to other internal addresses
      "to see what's reachable."
- [ ] **Do not** retrieve credentials from IMDS even if the response path
      is open.

Outbound-request-confirmed is a complete report. Anything past that line is
exploitation of internal infrastructure and is out of scope on essentially
every bug-bounty program.
