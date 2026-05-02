# Wiring Mirage into Wazuh

Mirage emits a structured JSONL stream that Wazuh's built-in JSON decoder
can ingest with no custom parsing. This doc walks through the manager-side
config end-to-end.

## 1. Run Mirage with a deterministic audit-log path

```sh
./build/mirage \
  --host :: \
  --port 5432 \
  --audit-log /var/log/mirage.jsonl
```

The file path you pick has to be readable by the user the Wazuh agent runs
as (`wazuh` on most distros). Either chown it after Mirage creates the file
or run Mirage as the same user.

## 2. Add a `<localfile>` block on the agent

Edit `/var/ossec/etc/ossec.conf` on the host running Mirage and add:

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/mirage.jsonl</location>
  </localfile>
</ossec_config>
```

Restart the agent: `systemctl restart wazuh-agent`.

## 3. Install decoders and rules on the manager

Copy the bundled files onto the Wazuh manager:

```sh
cp docs/wazuh/decoders.xml /var/ossec/etc/decoders/local_decoder.xml
cp docs/wazuh/rules.xml    /var/ossec/etc/rules/local_rules.xml
/var/ossec/bin/wazuh-control restart
```

## 4. Verify the rules are firing

```sh
echo '{"event":"detection","rule":"conn_rate_spike","src_ip":"203.0.113.7","count":"11","window_s":"60"}' \
  | /var/ossec/bin/wazuh-logtest
```

You should see the event matched by rule `100130` at level 10.

## Rule severities at a glance

| event                       | rule id | level | meaning                                           |
|-----------------------------|--------:|------:|---------------------------------------------------|
| any (parent)                |  100100 |   3   | honeypot saw a thing                              |
| `password`                  |  100110 |   5   | one credential harvested                          |
| `query`                     |  100120 |   5   | one query observed                                |
| `detection: conn_rate_spike`|  100130 |  10   | sustained connection burst from one IP            |
| `detection: auth_spray`     |  100131 |  10   | many distinct usernames from one IP               |
| `detection: suspicious_query`| 100132 |  12   | catalog enumeration — page on-call                |
| `ratelimit_drop`            |  100140 |   5   | accept-layer drop (post-burst attacker)           |

Tune by editing `docs/wazuh/rules.xml`. The level-12 `suspicious_query` rule
is intentionally aggressive because Mirage's only legitimate clients are
your own tests; a real client touching `pg_authid` should ring a phone.

## Troubleshooting

- **No events show up in Wazuh**: confirm the agent has read permission on
  `/var/log/mirage.jsonl` (`sudo -u wazuh cat /var/log/mirage.jsonl`).
- **Events arrive but nothing matches**: run the JSON line through
  `wazuh-logtest` — the parent `mirage-json` decoder must match before
  any child rule fires.
- **Rule IDs collide**: if you already use the 100100–100199 range, change
  the ids in `rules.xml`. Wazuh requires custom rules to be in the 100000+
  range.
