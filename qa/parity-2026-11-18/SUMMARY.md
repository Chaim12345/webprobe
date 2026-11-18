# Lab parity re-measure, 2026-11-18

Stored Burp issue lists (burp-scan7/8/9/10.json, paths.txt, diff-final.txt,
lab.py, burp-browser-crawl-scan5.json) lived in /tmp and are gone; Craft keeps
only their hashes. Burp side available: per-type counts of scan 7 (fnd_68):
CORS arbitrary origin 25, CORS 25, Input returned (reflected) 4, Unencrypted
communications 1, Robots.txt 1, OpenAPI (active) 1, Path-relative style sheet 1
(58) + 2 known WebProbe-only locations (/ftp/legal.md, /ftp/announcement_encrypted.md).

Redone: Juice crawl-and-audit from / (live_juice_crawl_scan) through a counting
forwarder (tools/count_proxy.py, 127.0.0.1:3101 -> 3001), at 4 trees:

| tree | commit | issues | requests |
|---|---|---|---|
| before-d11 | 09ed7a9 | 73 | 6175 |
| after-d11 | ec380b4 | 73 (identical) | 7267 |
| after-d09 | e7b5eff | 73 (identical) | 6181 |
| after-d10 | working tree (D-10 + FPM fix) | 64 | 5473 |

Not redone: Juice 75/75 (paths.txt gone), lab 21/21 and 18=18 (lab.py gone).
