# Thndr Security CTF — Internship Assessment Report

**Candidate:** Abdelrahman El-Maghraby
**Email:** abdelrahmanfekrymaghrby@gmail.com
**Date:** 24-25 May 2026
**Environment:** `https://play.thndr-ctf.app/`
**Cluster:** Amazon EKS (eu-central-1)
**Namespace:** `c-abdelrahmanfekrymaghrby-gmail-com`

## Executive Summary

The Thndr internal Operator Console exposes a chained set of vulnerabilities that allow an attacker to progress from a public login page all the way into the Kubernetes data plane of the cluster hosting it. This report documents four confirmed exploitation paths (F1–F4) and the partial findings for the fifth (F5), the lessons learned, and the recommended remediations.

---

## 1. Flag 1 (F1) — SQL Injection (Authentication Bypass)

* **Discovery:** The `/login` endpoint concatenates user input directly into a SQLite query without parameterisation. Injecting `admin'--` into the username field commented out the password check entirely, returning the `admin` row and creating a valid operator session where F1 was rendered into the dashboard banner. Source was later confirmed via the F2 RCE (`/app/app.py`):

  ```python
  q = f"SELECT id, username, role FROM users WHERE username = '{u}' AND password = '{p}'"
  ```

* **Dead-ends & Wrong Turns:** I first tried the literal pre-filled hint `' OR '1'='1` in the password field — it authenticated me but as the first user returned (not admin). Then I tried `admin' OR '1'='1'--` against the username, which broke the SQL syntax due to the dangling quote. Finally `admin'--` worked cleanly.

* **Remediation:**
    * Use parameterised queries (`_db.execute("... WHERE username = ? AND password = ?", (u, p))`).
    * Store password hashes (bcrypt/argon2) instead of plaintext.
    * Delegate authentication entirely to Cloudflare Access rather than re-implementing a custom login form.

---

## 2. Flag 2 (F2) — OS Command Injection (RCE as root)

* **Discovery:** The post-login `/diag?host=` endpoint executes user input via `subprocess.run(..., shell=True)`. The payload `127.0.0.1; cat /app/flag2.jwt` ran in the same shell context as root and printed F2 to the dashboard. Source confirmed:

  ```python
  cmd = f"ping -c 1 -W 1 {host}"
  subprocess.run(cmd, shell=True, ...)
  ```

* **Dead-ends & Wrong Turns:** I first tried command substitution with backticks ``` `cat /app/flag2.jwt` ``` and `$(cat ...)`, expecting them to execute pre-`ping` — they did, but `ping` then tried to resolve the file contents as a hostname and the output was buried in errors. A simple `;` separator was much cleaner. I also over-engineered the URL encoding (`%3B`, `%20`, etc.) when the raw characters worked fine inside the form field.

* **Remediation:**
    * Never use `shell=True` with user input. Use the list form: `subprocess.run(["ping","-c","1","-W","1", host])`.
    * Strictly validate `host` against a hostname/IP regex *before* invoking any subprocess.
    * Run the container as a non-root UID and apply `readOnlyRootFilesystem: true`.

---

## 3. Flag 3 (F3) — Kubernetes Secret Read via RBAC Abuse

* **Discovery:** After F2 gave me a shell, I read `/var/run/secrets/kubernetes.io/serviceaccount/token` (the auto-mounted `pod-a-sa` token). A `SelfSubjectRulesReview` POST to the API showed `get secrets resourceNames=[flag3]`. Reading `/api/v1/namespaces/<ns>/secrets/flag3` and base64-decoding `data.flag3.jwt` returned F3.

* **Dead-ends & Wrong Turns:** I first tried `list secrets`, expecting to enumerate everything — the metadata came back but `data` fields were redacted for secrets I didn't have `get` on. I then guessed names (`flag1`, `flag5`, `admin`, `default-token`) before realising I should let RBAC tell me what I could read via `SelfSubjectRulesReview`. I also wasted time trying to use `kubectl` from the pod (not installed) before switching to raw `urllib` + a Bearer header.

* **Remediation:**
    * Set `automountServiceAccountToken: false` on every pod that doesn't need API access — a Flask front-end never does.
    * Apply a NetworkPolicy denying egress to `172.20.0.1` from application pods.
    * Enable etcd encryption at rest.

---

## 4. Flag 4 (F4) — Kubernetes Pod Exec (Lateral Movement)

* **Discovery:** `pod-a-sa` also held `create, get pods/exec resourceNames=[pod-b]`. Pod-B is a separate workload in the namespace running BusyBox `httpd -h /www` with the `flag4` ConfigMap mounted at `/flag4.jwt`. I established a WebSocket connection to the exec endpoint with subprotocol `v4.channel.k8s.io`, ran `cat /flag4.jwt`, and extracted F4 from the stdout frames.

* **Dead-ends & Wrong Turns:** I first tried a plain HTTPS `POST` to the exec endpoint with `urllib` and kept getting `400 Bad Request` — I assumed an RBAC issue and re-verified my rules before realising `pods/exec` uses the SPDY/WebSocket streaming protocol, not plain HTTPS. I had to `pip3 install --break-system-packages websockets` into the running pod. I also wasted time treating the first byte of each WebSocket frame as data — it's actually the channel ID (1=stdout, 2=stderr); stripping it fixed the garbled output. Earlier, I also scanned pod-b's HTTP endpoint (`/flag4.jwt`, `/healthz`, path traversal) thinking the flag would be served over HTTP — only `/healthz` existed because the httpd's docroot was `/www`, not `/`.

* **Remediation:**
    * Treat `pods/exec` as equivalent to cluster-admin over the target pod — never grant it to a workload SA.
    * Mount sensitive material as Kubernetes Secrets (encrypted at rest) rather than ConfigMaps.

---

## 5. Flag 5 (F5) — Privilege Escalation to `flag-keeper` (Partial)

* **Discovery:** The `pod-b-sa` token (extracted via F4) held additional permissions: `get,list pods,serviceaccounts,configmaps`, `get pods/log`, and **`create, delete pods`**. Listing service accounts revealed a fourth identity named `flag-keeper` — no bound pods, no secrets, no IRSA annotation. The intended path was clear: create a pod that uses `flag-keeper` as its service account, have it print its mounted token to stdout, then read the pod log (which `pod-b-sa` is permitted to do). I successfully crafted a PodSpec running under the `flag-keeper` identity (with `limits.cpu/limits.memory` set to satisfy the namespace `ResourceQuota` named `candidate-quota`) and got the pod admitted to the cluster. Reading the pod's log via `pods/log` returned the `flag-keeper` SA JWT.

* **Dead-ends & Wrong Turns:**
    1. I tried `TokenRequest` against the `flag-keeper` SA using both `pod-a-sa` and `pod-b-sa` tokens — both returned 403.
    2. I tried creating a pod with `serviceAccountName: flag-keeper` and got 403. I misread the error message as RBAC for hours, only later realising it was a `ResourceQuota` rejection: the spec was missing `resources.limits.{cpu,memory}`. Once I added `limits: {cpu: 100m, memory: 64Mi}` the pod was admitted.
    3. While testing token extraction in pod-b, an over-long `cat $(cat .../token)` command triggered a `File name too long` error in the shell. Ironically that error printed the full `pod-b-sa` JWT directly into stderr, giving me a fresh token without needing to re-exec.
    4. With the `flag-keeper` token in hand, I called `SelfSubjectRulesReview` in my own namespace — it returned only the default `selfsubject*` review verbs and nothing else. I attempted targeted `GET` requests against `secrets/flag5`, `configmaps/flag5`, and many name variants (`flag-5`, `keeper`, `final`, `f5`, `flagkeeper`, `flag-keeper`) — all 403.
    5. The `flag-keeper` SA appears to have permissions scoped to a different namespace or as a cluster-scoped rule with `resourceNames` restrictions that don't surface in a per-namespace `SelfSubjectRulesReview`. Listing namespaces returned 403, so I could not enumerate them, and the dashboard banner "Settlement: degraded" hinted at a `settlement` service I never managed to locate via DNS within the time budget.
    6. The `/diag` endpoint enforces a strict 4-second `subprocess.run` timeout, which forced me to break the chain into separate short HTTP requests with intermediate state stored in `/tmp/` files. This worked, but cost time.

* **Remediation:**
    * Replace permissive `create pods` RBAC rules with a controller/Job pattern that enforces a fixed PodSpec.
    * Add a `ValidatingAdmissionPolicy` that rejects pods whose `serviceAccountName` is not in an allow-list.
    * Restrict `pods/log` to operator-only roles — logs frequently leak tokens (this CTF demonstrates the pattern exactly).
    * Enable Kubernetes audit logging at `RequestResponse` level for `secrets`, `pods/exec`, `pods/log`, and `TokenRequest`. Alert on any non-controller principal performing these.
    * A namespace NetworkPolicy denying egress to `172.20.0.1` from workload pods would have shut down F3, F4, and F5 entirely.

---

## Appendix A — Remediation & Security Posture

The following remediations are recommended to harden the Operator Console and the underlying EKS cluster:

1.  **Input Validation & Query Security:** Transition to using an ORM (like SQLAlchemy) or parameterised SQL queries to eliminate SQL injection vectors.
2.  **Execution Isolation:** Replace `subprocess.run(shell=True)` with API-based execution or restricted, shell-less execution environments.
3.  **RBAC Hardening:** Implement the "Principle of Least Privilege" (PoLP). Audit and remove `automountServiceAccountToken` for pods that do not require K8s API access. 
4.  **Workload Identity:** Use IRSA (IAM Roles for Service Accounts) to map fine-grained IAM policies to service accounts, limiting the blast radius of any compromised pod.
5.  **Policy Enforcement:** Deploy `Kyverno` or `OPA Gatekeeper` to enforce Pod Security Standards and restrict privileged execution permissions (e.g., preventing `pods/exec` by default).
