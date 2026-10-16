# Node provisioning checklist

Companion checklist for an administrator adding a Linux VPN node. Diagnostics do not apply these configuration changes automatically. Adapt each step to the installed core, panel, clients and network; keep a scoped backup and rollback before changing a running service.

## Prepare

- Read current primary documentation and relevant [host.pink guides](https://host.pink/baza/transporty/selfsteal/). Check installed versions rather than copying a guide's historical “latest” label.
- Check CPU steal, memory, disk and the actual client-to-server route. Bound benchmark traffic and load. Inspect remote scripts before executing them.
- Establish key-based SSH, a separate tested recovery route and private configuration backups. Keep secrets, full subscription URLs, client identifiers and private inventory out of public reports and Git.

## Public entry and website

- Use a node entry IP separate from the control panel. Choose a neutral domain label without provider, location or protocol terms; point DNS to the actual entry. Direct REALITY uses DNS-only records. Add IPv6 records only after testing IPv6.
- For direct REALITY selfsteal, host a real local HTTPS website, a trusted certificate for that neutral name, matching SNI/serverNames and a local TLS target. Verify the site without VPN credentials. A remote control-panel website does not supply this local arrangement.
- Expose the selected public TCP 443 entry. Keep backend TLS and management listeners private; do not expose alternate TLS/debug ports by default. Check Docker bindings and both IPv4/IPv6 firewall behavior externally.
- Keep HTTP 80 when required for webroot ACME, with the ACME exception and normal HTTP-to-HTTPS redirect. Verify trusted TLS 1.2/1.3 and real HTML. Add HSTS after HTTPS is verified; assess includeSubDomains/preload separately.
- Verify certificate renewal, the deployed certificate paths and a hook that reloads only the affected TLS service. Test renewal in staging/dry-run as supported by the ACME client.

## Transport and access

- For ordinary RAW/TCP REALITY, use a supported Vision configuration and a tested Firefox/QQ fingerprint where supported. Check the actual subscription emitted for the intended clients. Do not copy TCP flow/mux parameters blindly into XHTTP or other transports.
- Match PROXY protocol on both sides of every stream hop; do not forward a PROXY header into an ordinary TLS listener.
- Enable public UDP/QUIC only when required. Validate legitimate SNI, certificates and real HTTP/3/masquerade behavior. Reject unknown SNI only after testing support on the exact installed core: legitimate verified HTTP/3 requests/reconnects must work while an unknown SNI is rejected before HTTP, even if the test client ignores certificate verification. Preserve any legitimate subscription endpoint sharing this transport.
- Restrict node management to its control panel or private route. Check provider firewall, host firewall, container NAT and IPv6 together. Verify both denial from an unrelated source and success over the allowed management route.
- Use SSH keys and disable network password/keyboard-interactive login only after new key sessions and recovery access work. Validate SSH configuration and keep an automatic rollback while changing access controls. Preserve the existing recovery keys and routes.
- Keep databases, Redis, Docker APIs, debug/QA and metrics private or properly authenticated. Protect logs from tokens and subscription secrets. Use supported panel features/APIs; avoid maintaining patches to its frontend.

## Publish and record

- Test the actual emitted client profile from the intended user network before publishing: expected exit IP, HTTPS, bounded download/upload and reconnect. A successful datacenter test does not prove client-network reachability.
- Preserve existing customer keys, quotas, balances, roles and subscription dates. During a migration retain cached-client compatibility until it is safe to retire the old route. Verify Auto/generated profiles as well as the panel form.
- Verify DNS, trusted certificates, unauthenticated website, renewal, public ports, management isolation and authenticated VPN access before declaring selfsteal complete.
- Check the panel, affected services and independent recovery paths again after publication. Record versions, provider/cost/renewal, certificate expiry, tests, limitations and the scoped rollback in private inventory.
- Treat pending OS reboots and tuning as separate planned work on production servers. Inspect kernel/qdisc before BBR/fq changes; avoid unexplained sysctl/IPv6 changes.
- Open SSH and one TLS record size do not establish VPN detection. These checks do not guarantee indistinguishability from arbitrary DPI or availability on every mobile network.

Primary implementation references: [Xray](https://xtls.github.io/config/), [Remnawave](https://docs.rw/), [Nginx stream SNI preread](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html), [Certbot renewal](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates), [OpenSSH](https://man.openbsd.org/sshd_config).
