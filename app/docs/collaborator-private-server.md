# Running a private Collaborator server

WebProbe's Collaborator client talks the interactsh protocol. A private server
keeps payload traffic off the shared public servers (oast.pro and others) and
is what an engagement whose rules of engagement forbid third-party
callback services needs.

## 1. DNS

Pick a domain you control, for example `oast.example.com`, and a host with a
public IPv4 address (`203.0.113.10` below).

At the registrar for `example.com`, delegate the subdomain to that host:

```
ns1.oast.example.com.  A   203.0.113.10
ns2.oast.example.com.  A   203.0.113.10
oast.example.com.      NS  ns1.oast.example.com.
oast.example.com.      NS  ns2.oast.example.com.
```

## 2. Server

On the host, open TCP 25, 53, 80 and 443 and UDP 53, then run the
interactsh server (Go 1.21+):

```
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest
interactsh-server -domain oast.example.com -ip 203.0.113.10 -token "$(openssl rand -hex 24)"
```

The server gets a Let's Encrypt certificate for the domain on first start.
`-token` makes registration and polling require that token. Leave it out
for an open server, but only on a private network.

Add `-eviction 1` (days) for the server to forget interactions quickly.
Use `-http-port`/`-https-port` if 80/443 are taken.

## 3. WebProbe

Collaborator tab, gear icon, "Collaborator server (interactsh)":

| Field | Value |
|---|---|
| Server | `oast.example.com`, or `oast.example.com:8443` for a non-standard HTTPS port |
| Auth token | the `-token` value (sent as the `Authorization` header) |
| Poll every | seconds between polls (default 3; applies to a running session) |
| Keep interactions for | minutes before an interaction leaves the list (`ever` = until the 500 most recent) |

Click **Use server**. The status line shows `*.oast.example.com`, and new
payloads are generated under that domain. Scanner out-of-band checks use the
same session.

## Checking it

```
dig +short test123.oast.example.com @ns1.oast.example.com
curl -s https://test123.oast.example.com/ >/dev/null
```

Then **Poll now**. Payloads from WebProbe's own correlation id show up in the
list. Lookups made by hand with other ids do not, because the server only
reports interactions for the registered id.

## Troubleshooting

- `register ... failed: HTTP 401`: the token is wrong or missing.
- `connect ...` / `resolve ...`: the API host:port is unreachable from this
  machine. The API is HTTPS on 443 unless you gave a port.
- `tls: ...`: the server's certificate is not trusted, for example while it
  is still obtaining one. WebProbe verifies the certificate against the system
  roots.
