# make-snmprec

Convert SNMP walk results into `.snmprec` inputs for repeatable network-tool testing. The implementation is a small Go command in `main.go` using SNMP v2c.

## Build from source

```sh
go build -o /tmp/make-snmprec-demo .
```

Inspect the flags in `main.go` before connecting. Use an authorized lab device or simulator and a lab-only community. `192.0.2.10` is a documentation address, not a working target.

## What to inspect

- SNMP walk and supported PDU-to-record type conversion.
- String escaping and non-text handling.
- Output record shape: `OID|type|value`.

The existing tracked executable is a historical artifact. Build from the reviewed source instead of assuming the artifact matches current code or your platform.
Do not upload real device inventories, hostnames, serial numbers or community values as captures. Live walks and simulator replay are separate verification steps.

[network-collector](https://github.com/swlee3306/network-collector) · [Project map](https://github.com/swlee3306#selected-work)
