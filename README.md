# ns_to_skudonet — NetScaler → Skudonet Migration Tool

Converts a Citrix ADC (NetScaler) `ns.conf` configuration file into
[Skudonet (ZEVENET)](https://www.skudonet.com/) load-balancer configuration,
producing:

| Output file | Purpose |
|---|---|
| `skudonet_config.json` | Full structured JSON — farms, services, backends, certificates, health checks |
| `skudonet_apply.sh` | Bash script of `curl` calls against the Skudonet ZAPI v4.0 REST API |

**Intentionally skipped** (assumed handled separately by the operator):
- VLAN configuration (`add vlan`, `bind vlan`)
- Floating IP / SNIP addresses (`add ns ip -type SNIP`)
- HA / cluster configuration
- GSLB vservers (noted in unhandled output)
- Syslog / audit / AAA configuration

---

## Requirements

| Requirement | Detail |
|---|---|
| Python | 3.6 or newer |
| Dependencies | **None** — pure stdlib only |
| Platform | Windows, Linux, macOS |

---

## Installation

No installation needed. Copy `ns_to_skudonet.py` anywhere and run with Python 3.

```bash
# Windows
python ns_to_skudonet.py ns.conf

# Linux / macOS
python3 ns_to_skudonet.py ns.conf
```

---

## Usage

```
usage: ns_to_skudonet [-h] [--output-dir DIR] [--dry-run] [--verbose] ns.conf

positional arguments:
  ns.conf              Path to the NetScaler ns.conf file

optional arguments:
  -h, --help           Show this help message and exit
  --output-dir DIR, -o DIR
                       Directory for output files (default: current directory)
  --dry-run, -n        Parse and report without writing any output files
  --verbose, -v        Print verbose progress information
  --api-format {bash,powershell}
                        Output format for API calls: bash (default) or powershell
```

### Examples

```bash
# Basic conversion – writes to current directory
python ns_to_skudonet.py /path/to/ns.conf

# Write output to a dedicated directory
python ns_to_skudonet.py ns.conf --output-dir ./migration_output

# Dry run – inspect what would be converted without writing files
python ns_to_skudonet.py ns.conf --dry-run --verbose

# Verbose mode – shows counts at each stage
python ns_to_skudonet.py ns.conf -v -o ./output

# Generate PowerShell script instead of bash
python ns_to_skudonet.py ns.conf --api-format powershell
```

### Applying the shell script

```bash
# Set your Skudonet host and API key first
export BASE_URL="https://your-skudonet-appliance"
export API_KEY="your-zapi-key-here"

# Run the generated script
bash skudonet_apply.sh

# Stop on the first error (default is to continue and report)
ABORT_ON_ERROR=1 bash skudonet_apply.sh
```

---

## Architecture

The tool is structured in eight sections / classes:

```
NSConfigParser       Parse ns.conf → list of (verb, [args]) tuples
        │
        ▼
NetScalerModel       Build typed in-memory model (servers, SGs, vservers,
        │            monitors, SSL config, policies, …)
        ▼
SkudonetMapper       Convert NS model → Skudonet intermediate dicts
        │            (farms, services, backends, farmguardians, …)
       / \
      /   \
     ▼     ▼
Config   APIScript
Writer   Writer
  │        │
  ▼        ▼
.json    .sh
```

---

## Concept Mapping Reference

### Farm Profile Selection

| NetScaler Protocol | Skudonet Profile |
|---|---|
| HTTP | `http` |
| HTTPS | `http` (with https listener + cert) |
| SSL / SSL_BRIDGE / SSL_TCP | `http` |
| TCP | `l4xnat` |
| UDP | `l4xnat` |
| ANY | `l4xnat` |
| FTP, DNS, RADIUS, DIAMETER, MySQL, MSSQL, … | `l4xnat` |

### LB Method Mapping

| NetScaler lbMethod | Skudonet algorithm |
|---|---|
| ROUNDROBIN | `weight` |
| LEASTCONNECTION | `leastconn` |
| SOURCEIPHASH | `hash` |
| LEASTRESPONSETIME | `leastconn` *(closest equivalent)* |
| URLHASH | `hash` |
| LEASTBANDWIDTH | `leastconn` |
| LEASTPACKETS | `leastconn` |
| TOKEN | `weight` |
| SRCIPDESTIPHASH | `hash` |
| SRCIPSRCPORTHASH | `hash` |
| CALLIDHASH | `hash` |
| CUSTOMLOAD | `weight` *(fallback)* |

### Persistence Mapping

| NetScaler persistenceType | Skudonet mode | Notes |
|---|---|---|
| SOURCEIP | `IP` (HTTP) / `ip` (L4xNAT) | Direct equivalent |
| COOKIEINSERT | `COOKIE` | HTTP farms only |
| COOKIEPASSIVE | `COOKIE` | Skudonet inserts its own cookie |
| SSLSESSIONID | `IP` | No SSL session equivalent; review required |
| RULE | `IP` | Cannot auto-convert rule expressions |
| DESTIP | *(none)* | No Skudonet equivalent; manual review |
| SRCIPDESTIP | `IP` | Approximation |
| NONE / empty | *(no persistence)* | |

Persistence `ttl` maps to the NetScaler `-persistenceTimeout` value (or `-timeout` as fallback).

### Monitor / Health Check Mapping

| NetScaler Monitor Type | Skudonet FarmGuardian Command | Notes |
|---|---|---|
| HTTP | `check_http -H $HOST -p $PORT` | URL extracted from `-httpRequest` |
| HTTP-ECV | `check_http -H $HOST -p $PORT` | `-recv` maps to `-s` string check |
| HTTPS / HTTP_SECURE | `check_http -H $HOST -p $PORT --ssl` | |
| TCP | `check_tcp -H $HOST -p $PORT` | `-send` / `-recv` mapped to `-s` / `-e` |
| TCP-ECV | `check_tcp -H $HOST -p $PORT` | |
| PING / ICMP | `check_ping -H $HOST -w 100,5% -c 500,10%` | |
| DNS | `check_dns -H $HOST -p $PORT` | *(manual review recommended)* |
| SMTP / FTP / IMAP / POP3 | `check_tcp -H $HOST -p $PORT` | *(manual review)* |
| Custom / Unknown | `check_tcp -H $HOST -p $PORT` | *(manual review, noted)* |

One FarmGuardian is registered per farm. If a vserver has multiple service
groups with different monitors, only the first monitor is applied and the
rest are noted for manual review.

### SSL / Certificate Mapping

| NetScaler concept | Skudonet equivalent |
|---|---|
| `add ssl certKey` | Certificate upload to Skudonet |
| `bind ssl vserver -certkeyName` | Bind cert to HTTPS farm |
| `bind ssl vserver -certkeyName … -SNICert` | SNI certificate on HTTPS farm |
| `link ssl certKey` (certificate chain) | Chain cert noted; upload and link manually |
| `set ssl vserver -sslProfile` | SSL profile noted; translate cipher/protocol settings manually |
| `set ssl vserver -cipherName` | Cipher alias noted; translate to OpenSSL string |
| `-tls12 ENABLED` etc. | TLS protocol list recorded; configure in Skudonet SSL settings |
| `-clientAuth ENABLED` | Client certificate auth noted; configure CA cert manually |

> **Important:** Certificate PEM/key files must be uploaded to Skudonet
> before creating farms. The generated shell script includes commented-out
> `curl -F` upload stubs for each certificate.

### Content Switching Mapping

NetScaler CS vservers become Skudonet HTTP farms with multiple Services:

| NetScaler concept | Skudonet equivalent |
|---|---|
| `add cs vserver` | HTTP farm |
| `add cs policy -rule <expr>` | Service with URL pattern / hostheader |
| `add cs action -targetLBVserver` | Service with backends from that LB vserver |
| `bind cs vserver -policyName -priority` | Service ordering (by priority) |
| `bind cs vserver -lbvserver` (default) | Default catch-all service (`urlp=/`) |

**CS rule expression extraction (best-effort):**

| NS PIXL Expression | Extracted as |
|---|---|
| `HTTP.REQ.URL.STARTSWITH("/api")` | `urlp = /api` |
| `HTTP.REQ.URL.CONTAINS("/shop")` | `urlp = /shop` |
| `HTTP.REQ.URL.EQ("/home")` | `urlp = /home` |
| `HTTP.REQ.URL.MATCHES_GLOB("/img/*")` | `urlp = /img/*` |
| `HTTP.REQ.HOSTNAME.EQ("app.example.com")` | `hostheader = app.example.com` |
| `HTTP.REQ.HOST.EQ("api.example.com")` | `hostheader = api.example.com` |
| Classic: `REQ.HTTP.URL startswith "/admin"` | `urlp = /admin` |
| Complex (`AND` / `OR` / `&&` / `\|\|`) | Set to `/`, flagged for manual review |

### Responder Policy Mapping

| NetScaler responder action type | Skudonet equivalent |
|---|---|
| `redirect` | Redirect entry in farm (URL preserved, review required) |
| `respondwith` | Manual review — custom response not auto-convertible |
| `respondwithhtmlpage` | Manual review |
| `noop` / `reset` | Skipped |

### Rewrite Policy Mapping

| NetScaler rewrite action type | Skudonet equivalent |
|---|---|
| `insert_http_header` | `AddRequestHeader` directive (noted for manual config) |
| `insert_http_req_header` | `AddRequestHeader` directive |
| `delete_http_header` | `RemoveRequestHeader` directive (noted) |
| `replace` | `ModifyHeader` (noted for manual config) |
| `replace_http_res` | `ModifyHeader` response (noted) |
| Other / complex | Manual review note added |

All rewrite rules are preserved as structured comments in the shell script
with the original NS policy name, rule expression, target, and string-builder
expression so the operator has full context.

---

## Output File Details

### skudonet_config.json

```json
{
  "_generator": "ns_to_skudonet.py v1.0.0",
  "_source": "Citrix ADC (NetScaler) ns.conf",
  "_notes": [ "…" ],
  "certificates": [ { "name": "…", "cert_file": "…", "key_file": "…" } ],
  "farms": [
    {
      "farmname": "my_farm",
      "profile": "http",
      "vip": "10.0.0.1",
      "vport": 443,
      "status": "up",
      "algorithm": "weight",
      "https_listener": true,
      "ssl": { "certificates": ["myCert"], "ciphers": "HIGH:!aNULL:!MD5" },
      "persistence": { "persistence": "COOKIE", "ttl": 600, "cookie": "SERVERID" },
      "services": [
        {
          "id": "api",
          "urlp": "/api",
          "hostheader": "",
          "backends": [
            { "ip": "192.168.1.10", "port": 8080, "weight": 1, "status": "up" }
          ],
          "farmguardian": { "name": "fg_http_mon", "command": "check_http", "params": "…" }
        }
      ],
      "farmguardian": [ { "name": "fg_http_mon", "command": "check_http", … } ],
      "redirects": [],
      "rewrites": [],
      "_notes": [],
      "_ns_name": "vs_my_app",
      "_ns_type": "lb_vserver"
    }
  ],
  "manual_review_items": [ "…" ]
}
```

Fields prefixed with `_` are informational metadata and are not sent to the API.

### skudonet_apply.sh

The shell script is structured in clearly labelled sections:

1. **Header** — prerequisites, usage, `check_response` helper function
2. **SSL certificates** — commented-out upload stubs (uncomment and fill in paths)
3. **Per-farm blocks**, each with:
   - `POST /farms` — create the farm
   - `PUT /farms/<name>` — configure algorithm, listener, persistence
   - `POST /farms/<name>/certificates/<cert>` — bind SSL cert(s)
   - `POST /farms/<name>/services` — create service(s) (HTTP farms)
   - `POST /farms/<name>/services/<svc>/backends` — add backends (HTTP)
   - `POST /farms/<name>/backends` — add backends (L4xNAT)
   - `POST /farms/<name>/fg` — register FarmGuardian
   - Commented redirect/rewrite blocks with full NS context
   - `PUT /farms/<name>/actions` — start or stop the farm
4. **Footer**

---

## Migration Workflow

Follow this order to migrate safely:

1. **Run the tool in dry-run mode first** to see the summary and manual review items:
   ```bash
   python ns_to_skudonet.py ns.conf --dry-run --verbose
   ```

2. **Generate the output files:**
   ```bash
   python ns_to_skudonet.py ns.conf --output-dir ./migration
   ```

3. **Review `skudonet_config.json`** — particularly:
   - `manual_review_items` array
   - Any farm `_notes` fields
   - Persistence mappings with `_note` fields
   - SSL cipher/profile notes

4. **Upload SSL certificates** to Skudonet (via UI or the commented-out `curl` stubs in the shell script). Cert files must be in PEM format.

5. **Verify VIPs** exist as Skudonet virtual interfaces (these were handled separately).

6. **Test in a non-production environment first.** Set `ABORT_ON_ERROR=1` in the shell environment to stop on the first API error.

7. **Run the shell script:**
   ```bash
   export BASE_URL="https://your-skudonet-host"
   export API_KEY="your-api-key"
   bash migration/skudonet_apply.sh 2>&1 | tee migration.log
   ```

8. **Verify** each farm is running and health checks are passing in the Skudonet UI.

9. **Manually configure** any items listed under `manual_review_items` — these include complex rewrite/responder policies, SSLSESSIONID persistence, backup vservers, and compound CS rule expressions.

---

## Known Limitations

| Limitation | Detail |
|---|---|
| **One FarmGuardian per farm** | Skudonet supports one health-check profile per farm. If multiple service groups within one vserver use different monitors, only the first is applied. |
| **Complex CS rule expressions** | Composite expressions (`AND`, `OR`, `&&`, `\|\|`) cannot be auto-split. A `/` catch-all is used and a manual review note is added. |
| **Rewrite / Responder policies** | Only simple redirect and header-insert actions are approximated. Complex NS PIXL expressions, `respondwith` custom bodies, and most `replace` actions require manual Skudonet DirectiveRewrite configuration. |
| **SSLSESSIONID persistence** | No direct Skudonet equivalent. Mapped to IP persistence. |
| **RULE-based persistence** | Cannot auto-convert NS rule expressions. Mapped to IP persistence. |
| **DESTIP persistence** | No Skudonet equivalent. Noted, not applied. |
| **Backup vservers** | NetScaler's `-backupVServer` has no direct Skudonet equivalent. Noted for manual DR/failover configuration. |
| **SSL cipher aliases** | NetScaler cipher group names are not OpenSSL strings. Must be translated manually. |
| **SSL profiles** | `set ssl vserver -sslProfile` settings noted but not auto-applied. |
| **Client certificate auth** | Noted but CA certificate configuration must be done manually in Skudonet. |
| **GSLB vservers** | Not modelled. Appear in unhandled command list. |
| **Rate-limiting / AppFW policies** | Not converted. Appear in unhandled command list. |
| **Connection multiplexing** | NS `set ns timeout` values are noted but not all map to Skudonet timeout fields. |
| **Multiple monitors on one farm** | Only the first (by service group order) is applied as FarmGuardian. |
| **Backend maintenance state** | Disabled backends (from DISABLED service groups/services) are flagged with a comment. The backend ID is unknown at generation time so maintenance mode must be set manually after creation. |
| **Port \* (wildcard)** | NetScaler port `*` (any port) in vservers is not supported by Skudonet and will require a specific port value. |
| **Case sensitivity** | NetScaler entity names are case-sensitive. The tool preserves original casing; ensure Skudonet farm names are unique after sanitisation. |

---

## Troubleshooting

**`[FAIL] create-farm-<name>` — "farmname already exists"**
> The farm was already created in a previous run. Delete it in Skudonet first or skip that section of the script.

**`[FAIL] bind-cert-<name>` — "certificate not found"**
> Upload the certificate to Skudonet before running the farm sections.

**`[FAIL] create-service-<name>` — "service id already exists"**
> Re-running the script without first deleting the farm. Delete the farm completely and re-run.

**CS vserver service backends are empty**
> The CS policy targets an LB vserver that has no members bound in `ns.conf`. Check that `bind serviceGroup` entries appear after the `add serviceGroup` line in your config. Use `--verbose` to see counts.

**Lots of items in `manual_review_items`**
> This is expected for configs that use NS PIXL expressions, AppFW, responder/rewrite policies with complex logic. Review each item and configure the Skudonet equivalent manually.

---

## Example ns.conf Snippet and Expected Output

**Input (ns.conf excerpt):**
```
add server web01 192.168.1.10
add server web02 192.168.1.11
add serviceGroup sg_web HTTP -state ENABLED
bind serviceGroup sg_web web01 80
bind serviceGroup sg_web web02 80
add lb monitor mon_http HTTP -httpRequest "GET /health HTTP/1.0" -recv "OK" -interval 5
bind serviceGroup sg_web -monitorName mon_http
add lb vserver vs_web HTTP 10.0.0.100 80 -lbMethod ROUNDROBIN -persistenceType COOKIEINSERT -cookieName APPID -persistenceTimeout 600
bind lb vserver vs_web sg_web
```

**Output (skudonet_config.json excerpt):**
```json
{
  "farms": [
    {
      "farmname": "vs_web",
      "profile": "http",
      "vip": "10.0.0.100",
      "vport": 80,
      "status": "up",
      "algorithm": "weight",
      "https_listener": false,
      "persistence": { "persistence": "COOKIE", "ttl": 600, "cookie": "APPID" },
      "services": [
        {
          "id": "default",
          "urlp": "/",
          "backends": [
            { "ip": "192.168.1.10", "port": 80, "weight": 1, "status": "up" },
            { "ip": "192.168.1.11", "port": 80, "weight": 1, "status": "up" }
          ],
          "farmguardian": {
            "name": "fg_mon_http",
            "command": "check_http",
            "params": "-H $HOST -p $PORT -u /health -s 'OK'",
            "interval": 5
          }
        }
      ]
    }
  ]
}
```

---

## License

This tool is provided as-is for migration assistance. Review all generated
output carefully before applying to a production Skudonet appliance.
