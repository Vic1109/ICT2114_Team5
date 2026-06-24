# Offline JSON Alert Template Format

Use this when the Wazuh server is unavailable and you want to test report generation manually from the dashboard.

Upload a `.json` file in **Manual Alert Analysis -> Offline JSON Alert Template**.

Accepted shapes:

1. A single Wazuh-style alert object.
2. An array of Wazuh-style alert objects.
3. An object with an `alerts` array.
4. Newline-delimited JSON copied from `alerts.json`, one alert object per line.

Recommended wrapper format:

```json
{
  "alerts": [
    {
      "timestamp": "2026-06-05T10:15:00.000+0000",
      "rule": {
        "level": 10,
        "id": "100001",
        "description": "ET POLICY Suspicious inbound HTTP request"
      },
      "agent": {
        "ip": "192.168.56.10",
        "name": "test-web-server"
      },
      "data": {
        "src_ip": "203.0.113.45",
        "dest_ip": "192.168.56.10",
        "src_port": 44321,
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "event_type": "alert",
        "direction": "inbound",
        "alert": {
          "signature": "ET WEB_SERVER Possible WebShell Upload",
          "category": "Web Application Attack",
          "severity": 1,
          "action": "allowed",
          "signature_id": 2026001
        },
        "http": {
          "hostname": "victim.local",
          "http_method": "POST",
          "url": "/upload.php",
          "status": 200
        }
      }
    }
  ]
}
```

Minimum useful fields:

- `rule.level`: numeric severity. High severity starts at `8`.
- `rule.description`: analyst-readable rule description.
- `rule.id`: useful for correlation and RAG query construction.
- `timestamp`: event time.
- `agent.name` or `agent.ip`: affected host.
- `data.src_ip` and `data.dest_ip`: source/destination context.
- `data.alert.signature`: Suricata signature, if available.
- `data.alert.category`: alert category, if available.

Optional but useful fields:

- `data.src_port`, `data.dest_port`, `data.proto`, `data.app_proto`
- `data.event_type`, `data.direction`
- `data.http.hostname`, `data.http.http_method`, `data.http.url`, `data.http.status`
- `data.dns.query[0].rrname`, `data.dns.query[0].rrtype`, or direct `data.dns.rrname`, `data.dns.rrtype`
- `data.tls.sni`, `data.tls.version`, `data.tls.subject`, `data.tls.issuer`, `data.tls.ja3`, `data.tls.ja3s`
- `data.email.from`, `data.email.to`, `data.email.subject`, `data.email.attachment`, `data.email.mail_from_domain`, `data.email.url`
- `data.fileinfo.filename`, `data.fileinfo.md5`, `data.fileinfo.sha1`, `data.fileinfo.sha256`
- `data.smb.command`, `data.smb.share`, `data.smb.filename`, `data.smb.disposition`
- `data.modbus.function`, `data.modbus.unit_id`, `data.modbus.address`, `data.modbus.quantity`
- `data.flow.pkts_toserver`, `data.flow.bytes_toserver`, and related flow fields
- `data.files`
- `data.metadata.flowbits` and `data.metadata.flowints`

The app will clean and enrich this template the same way it cleans live Wazuh alerts. RAG context can still come from uploaded CTI documents even when no Wazuh archives are available.

Validation behavior:

- Each alert must be a JSON object.
- Each alert may be either the raw Wazuh object or an Elasticsearch-style object with the alert under `_source`.
- `rule`, `agent`, `data`, and common nested fields such as `data.alert`, `data.http`, `data.dns`, `data.tls`, `data.email`, `data.fileinfo`, `data.smb`, `data.modbus`, `data.flow`, and `data.metadata` must be JSON objects when provided.
- `data.dns.query` should be an array of objects. A single object is accepted and normalized into a one-item array.
- `data.files` must be an array when provided.
- `data.fileinfo` is accepted as a single-file shortcut and normalized into `data.files` when `data.files` is absent.
- Each alert must contain either `rule.description` or `data.alert.signature`; otherwise the app cannot produce a useful cleaned alert and will reject the upload.

Convenience normalization:

The dashboard upload path accepts a few flat fields and moves them into the Wazuh-style locations consumed by the cleaner:

- `rule_id` -> `rule.id`
- `rule_description` -> `rule.description`
- `rule_level` -> `rule.level`
- `src_ip` -> `data.src_ip`
- `dest_ip` or `dst_ip` -> `data.dest_ip`
- `alert_signature` -> `data.alert.signature`
- `alert_category` -> `data.alert.category`
- `signature_id` -> `data.alert.signature_id`

For best analysis, still prefer the Wazuh-style nested format shown above because it is exactly what the live SSH path reads from `alerts.json`.
