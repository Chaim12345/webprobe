# Host probes

React2Shell sends one synthetic multipart POST to / per host, only after the audited response has a Next.js or RSC fingerprint. It does not replay the audited request. Its single 500/flight-error marker is reported as Tentative, not confirmed code execution. This Burp issue type participates in normal issue/check filtering; it does not require WebProbe extra checks to be enabled.
