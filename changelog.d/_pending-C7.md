- **The destructive-command rule now recognizes four raw-socket egress shapes.** A `/dev/tcp`/`/dev/udp`
  redirection target, netcat/ncat/socat used in exec-on-connect (reverse/bind-shell) form, an
  `openssl s_client -connect` TLS handshake, and an inline Python/Node payload that opens a socket
  directly now step up to `AUTH` (new `raw_socket_channel` reason code for the first three; the fourth
  reuses `opaque_command`, the same bucket an opaque `bash -c` payload already lands in) instead of
  parsing as an ordinary benign command. Detection reasons about shape only and stays inside the
  existing adversarial command walk (chained `;`/`&&`/`|`, `$()`/backtick substitution, and the
  256-segment work cap all already cover it) — it is deliberately AUTH-only, never `BLOCK`. DNS-label
  exfil (`dig`/`nslookup`) is a separate, uncalibrated gap this slice does not close.
