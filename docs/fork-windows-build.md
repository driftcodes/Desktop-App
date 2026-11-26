# Fork: proxy for imported OpenVPN profiles (Windows)

This fork is Windscribe 2.25.8 (stable) with one feature added: the HTTP proxy from
**Preferences > Connection > Proxy Settings** is also used by imported OpenVPN TCP profiles, not only
by Windscribe's own servers.

## What changes when a proxy is set

- **Imported OpenVPN profiles** connect through the proxy. Only their `remote` lines that use TCP are
  dialed; UDP lines are skipped. A profile with no TCP `remote` is refused with a message.
- **Windscribe servers** connect only with OpenVPN TCP. In Automatic mode the other protocols are
  skipped; a manually chosen WireGuard, IKEv2, Stealth or WSTunnel is refused with a message. Nothing
  connects directly while a proxy is set.
- **Proxy check.** Before OpenVPN starts, the app checks that the proxy accepts a connection (3 seconds).
  If not, it stops with "Windscribe could not reach the proxy at …" instead of retrying forever.
- **Proxy on this PC (127.x.x.x).** OpenVPN normally adds a route sending its "remote" through your
  physical gateway; behind a proxy that remote is 127.0.0.1, which Windows refuses
  (`CONNECTED,ROUTE_ERROR`). The helper starts OpenVPN with `--redirect-private local`, whose `local`
  flag makes OpenVPN skip exactly that route. It goes on the command line because Windscribe's
  patched OpenVPN refuses `redirect-private` inside a config file. Each profile keeps its own routing: a full-tunnel profile stays full
  tunnel, and a profile that only routes, say, `10.20.0.0/16` keeps doing only that. This applies to
  Windscribe servers too, so you can remove the three lines you added to Advanced Parameters (keeping
  them does no harm):
  ```
  pull-filter ignore redirect-gateway
  route 0.0.0.0 128.0.0.0 vpn_gateway
  route 128.0.0.0 128.0.0.0 vpn_gateway
  ```
- **No direct contact with imported servers before connecting.** While a proxy is set, the app does not
  look up imported hostnames when it loads the folder, does not ping imported servers to show their
  latency, and does not add them to the firewall's allowed list. Their latency is therefore not shown.
  Turning the proxy off restores all three.
- **`CONNECTED,ROUTE_ERROR`** from OpenVPN now ends the attempt with a clear message instead of an
  endless "Connecting". This applies with the proxy off too (before, the attempt just hung until it
  timed out, or forever for an imported profile).
- **Profiles that use one hostname for UDP and TCP** (e.g. `remote vpn.example.com 1194 udp` and
  `remote vpn.example.com 443 tcp`) no longer hang at "Connecting". This was an existing Windscribe bug.
- With the proxy off, everything behaves as in the official app.

Emergency Connect is unchanged and never uses the proxy.

### Still direct (not changed yet)

- When you connect to an imported profile whose TCP `remote` is a hostname, the app looks it up with
  your normal DNS before handing the resulting IP to OpenVPN. Use IP addresses in `remote` lines to
  avoid this lookup. With the proxy on, UDP remotes are never looked up, and a profile with no TCP
  remote is refused without any lookup.
- While connecting and connected, the server's IP is on the firewall's allowed list (as in the official
  app). That permits traffic to it but does not send any. Only OpenVPN and Windows system services may
  use it, and it is removed when the connection ends, including after a `CONNECTED,ROUTE_ERROR`.
- While not connected (disconnected, connecting, or reconnecting after Wi-Fi or Throne drops) with a
  proxy set, the firewall on Windows allows your DNS servers (and ControlD's) only for Windscribe's own
  programs: the app (which does Windscribe's DNS lookups, including for hostname-based imported
  profiles), its bundled tools, ctrld and the helper service. The Windows DNS Client service is not on
  that list, so programs cannot route lookups through it either. Throne and other excluded apps keep
  their own split-tunnel permit. The API server addresses and the ping targets are not allowed at all
  in that state; the API goes through the proxy. If the helper cannot identify Windscribe's programs,
  it adds no permit for those DNS servers at all (rather than one for every program), keeps the rest
  of the firewall on, and the app logs the failure and retries on the next firewall update; until then
  Windscribe may be unable to look up hostnames.
- **DNS baseline: no DNS out of your Wi-Fi/Ethernet while the firewall is on (Windows).** Whenever
  Windscribe's firewall is on (connected, connecting, reconnecting, after your own Disconnect in
  Always On, and from boot with Always On, since its rules persist like the firewall's), DNS (port 53,
  UDP and TCP) sent out of a physical adapter is blocked for every program, to any address: your
  router, a public resolver, or one no adapter lists any more (for example after you switch the
  Wi-Fi's DNS to Google). The firewall's LAN permit (Allow LAN, and always for imported profiles)
  would otherwise let any program query the router directly. Only Windscribe's own programs and the
  apps excluded in Exclusive split tunneling (Throne) may still do so; while connected, a custom
  Connected DNS address is allowed too. DNS through the VPN adapter is not affected, and other LAN
  traffic (the router's web page, printers, file shares) still works. With the firewall on and the
  VPN not connected, ordinary programs therefore cannot look up names at all (they cannot reach the
  internet then anyway); local names that come from the router's DNS do not resolve either.
  Turning the firewall off removes the baseline.
- **DNS leak filter during a proxied session (Windows).** Windscribe has a second filter that blocks
  DNS (port 53, UDP and TCP) to the DNS servers of your physical adapters. With a proxy set it now
  stays on from the moment you click Connect until your own Disconnect, including reconnects and the
  time between one OpenVPN process exiting and the next one starting. Before, it went off whenever an
  OpenVPN process ended. If the session ends some other way while the firewall stays on (for example
  Throne stopped, so the next attempt cannot reach the proxy, or a route error, or sleep), the filter
  stays on too, until you turn the firewall off, log out, quit the app, or connect again.
  - **While not connected** (connecting, reconnecting, or kept after an error) it blocks DNS to every
    local-network address (10.x, 172.16-31.x, 192.168.x, 169.254.x and the IPv6 equivalents), not just
    the router it knows about, so a router on a Wi-Fi network you join in the middle of a reconnect is
    blocked before the app has even seen it. Public DNS servers on your adapters are blocked too. Only Windscribe's own programs
    and the apps excluded in Exclusive split tunneling (Throne) may still use DNS there. A custom
    Connected DNS address is not exempt in this state either.
  - **While connected** it blocks your adapters' DNS servers for every program, except a custom
    Connected DNS you chose, as in the official app. A proxied connection is only reported as
    Connected once the helper has confirmed these rules; if it cannot, Windscribe disconnects with the
    DNS leak protection error rather than stay connected with the reconnect-time rules (which still let
    Windscribe and Throne reach those DNS servers).
  - **When a DNS server changes**, on a new network or on the same Wi-Fi (a DHCP renewal or a manual
    DNS change), the helper notices it (it watches where Windows keeps each adapter's DNS settings,
    and checks every 2 seconds as a backup) and rebuilds the filter. This also applies to the filter
    of connections without a proxy.
  - Other LAN traffic (printers, file shares, the router's web page) is not affected.
  - **If Windows cannot apply a change**, the helper keeps the rules that were in place and reports
    the failure; the app and the helper keep retrying (the app backs off from 2 seconds to a minute).
    If the adapters cannot be read while not connected, the local-network ranges and the DNS servers
    known from before are still blocked. A missing permit for Windscribe's own programs fails closed:
    the blocks go in, Windscribe may be unable to look up hostnames until a retry succeeds.
  - **No connection attempt without the filter.** With a proxy set, Windscribe does not start an
    attempt, the first one or any automatic reconnect or retry, until the helper has confirmed exactly
    the not-connected rules above. Rules confirmed earlier do not count if they are different ones
    (for example the connected rules still in place when a reconnect starts) or if a connection without
    a proxy has used the filter since. If it cannot get them, you get "Windscribe could not set up its
    DNS leak protection, so it did not connect" (also in the middle of a reconnect); it keeps trying in
    the background, so connecting again a moment later usually works.
  - **One owner at a time.** The filter is shared with Windscribe's ordinary (no proxy) connections,
    whose OpenVPN turns it on and off itself. While a proxied session holds it, the helper ignores
    those requests, so switching location from a connection without a proxy to one with a proxy cannot
    have the old connection remove the new one's filter as it shuts down. Who holds the filter follows
    the proxy setting of the connection you pick, decided the moment you pick it (also while the
    previous one still shows Connecting): a proxied one takes the filter at once; one without a proxy
    lets the previous session keep it until that session has ended, then hands it to its own OpenVPN
    (also after a proxied session ended with an error). The hand-over leaves the rules in place until
    that OpenVPN replaces them, so there is no moment without a filter in either direction, and the
    direct connection starts only once the helper has confirmed the hand-over. If it never does, the
    attempt stops with the DNS leak protection error and the previous rules stay (with the firewall on,
    until you turn it off). A direct connection (OpenVPN, WireGuard or IKEv2) that cannot install its own rules does not start either.
  - **The proxy setting is taken when you pick a location.** Everything that request leads to (the
    connection after the previous one has ended, a retry after fetching server credentials, the
    filter's hand-over) uses the proxy settings it was made with, and so do Windscribe's own requests
    meanwhile (the API, including the server-credential fetch before a redial, the firewall's proxy
    exception, probes of imported servers). Turning the proxy off or changing its port during a
    connection takes effect for all of these when that connection ends or you pick a location again
    (picking one applies its setting to these at once, also without disconnecting first); it does not turn a profile you
    picked with Throne into a direct connection, and Windscribe's API requests do not go direct either.
    Pick the location again to use the new setting.
  - Removing an app from the Exclusive exclusions takes away its DNS permit too; if that rebuild fails,
    the helper retries until the permit is gone.

  Limits:
  - A program that sends DNS to some other address or port (DNS-over-HTTPS to a public resolver, for
    example) is not covered by this filter; the firewall covers it while it is on.
  - After your own Disconnect this filter is off, as in the official app; with Always On the DNS
    baseline above keeps blocking DNS out of the physical adapters.
  - A public DNS server handed out by a network joined during a reconnect is covered once the helper
    sees the change, normally within 2 seconds (local-network ones are covered from the start). While
    connected, a new DNS server is likewise covered within about 2 seconds.
  - A program that needs DNS to a server on your LAN (for example a local Pi-hole you query directly)
    cannot reach it while a proxied session is not connected.
  - Throne has to resolve its own server's name itself, or use an IP address: lookups it hands to the
    Windows DNS Client service are blocked while a proxied session is not connected.
  - macOS and Linux keep upstream's behaviour (DNS servers allowed for every program).
  - Without a proxy nothing changes from the official app.
- **Always On at boot (before the app starts).** The Windows controller does not use the list it is
  given for the boot-time firewall: the helper simply keeps the rules it last applied, which persist
  across a restart, and the DNS baseline persists with them. When the service starts it keeps the
  baseline from before (which already permits your excluded apps) until the app has sent its split
  tunneling list, then rebuilds it. The DNS leak filter itself does not persist; it is set up again
  when you connect. A network adapter added while Windows was off is covered once the service has
  started. This has not been confirmed on a real Windows restart yet.

### Reconnecting

When the tunnel drops and the app reconnects, Windscribe's own API requests go through the proxy again
(the official app leaves them going directly until the next full disconnect), the firewall switches
to the not-connected list described above, and the DNS leak filter stays on throughout.

### Firewall behaviour

In Automatic mode the firewall only stays on after connecting when the tunnel carries all IPv4 traffic.
The app now decides this the way OpenVPN does, from the profile and everything the server pushed: the
profile's own `redirect-gateway`, its own `0.0.0.0/1` + `128.0.0.0/1` routes, or a pushed
`redirect-gateway` (with or without `def1`) or pushed `/1` routes that the profile does not drop with
`route-nopull` or a matching `pull-filter` (a case-sensitive prefix match, quotes included). A
`redirect-gateway` carrying `!ipv4`, pushed or not, means IPv4 is not redirected. Routes count when they go through
the tunnel (`vpn_gateway`, `default`, no gateway, the pushed `route-gateway`, the `ifconfig` peer, or an
address on the tunnel's subnet), and together they must cover all IPv4 addresses (two `/1`s, four
`/2`s, `0.0.0.0/0`, or any other split). As in a real routing table, a more specific route wins: a
profile that sends, say, `203.0.113.0/24` through `net_gateway` is not a full tunnel, so Automatic mode
turns the firewall off for it rather than blocking that traffic. Direct routes to private ranges
(`10/8`, `172.16/12`, `192.168/16`, `169.254/16`) and multicast don't count: for an imported profile
the firewall always allows those off the tunnel, whatever the Allow LAN setting. That includes a route over
`10.255.255.0/24` (Windscribe's in-tunnel DNS, e.g. a local `10.0.0.0/8` route): the firewall keeps
blocking that range off the tunnel on its own, so it is no reason to turn the whole firewall off. A direct route to the VPN server itself doesn't count either: the
firewall lets OpenVPN and Windows system services reach that address (other programs still can't).
On Windows, OpenVPN adds `def1` to every `redirect-gateway` (Windscribe runs it in service mode), so
`redirect-gateway` and `redirect-gateway def1` are treated the same. When a direct route has exactly the
same prefix as a tunnel route, which one Windows uses depends on route metrics; the app treats that tie
as the tunnel, which keeps the firewall on. Only lines that actually reach OpenVPN count: the
helper strips `route-noexec` and `redirect-private` from imported files, so they are ignored here too.
The decision is made once connected, from the profile and the server's push together. Before,
an imported profile with `pull-filter ignore redirect-gateway` (even with its own full routes), or one
whose `redirect-gateway` was in the file rather than pushed by the server, made Automatic / Before
Connection switch the firewall off once connected. A profile that really only routes some networks
still switches it off, because blocking everything else would cut your internet. **Always On** never
switches the firewall off.

## Checking for DNS leaks (Windows)

Test with an app that is **not** excluded from the tunnel (not Edge, if you exclude it; for example
`nslookup` from a Command Prompt, or a browser you did not exclude) and watch the **physical Wi-Fi
adapter** with Wireshark (filter: `udp.port == 53 || tcp.port == 53`). Find your Wi-Fi DNS server with
`ipconfig /all` (usually your router, 192.168.x.x).

1. Connect with the proxy set. Run `nslookup example.com <your Wi-Fi DNS server>` and
   `nslookup example.com 1.1.1.1`. Neither may show up on the Wi-Fi capture (both should fail or go
   through the tunnel).
2. Make the tunnel drop and reconnect: turn Wi-Fi off and on. While the app shows Connecting, repeat
   both lookups (a loop helps; replace 192.168.1.1 with your Wi-Fi DNS server:
   `for /l %i in (1,1,60) do nslookup example.com 192.168.1.1 & timeout /t 1`). Neither may reach the
   Wi-Fi DNS server or 1.1.1.1 on the capture. Windscribe itself and Throne may still show DNS traffic
   there; that is expected.
3. While it shows Connecting, join a different Wi-Fi network (or a phone hotspot) whose router has
   another address, and query that router the same way: it must not appear on the capture either.
   Then, while connected, start a loop querying another address on your LAN once a second (as above,
   with that address), and while it runs change the Wi-Fi adapter's DNS server to that address by hand
   (Settings > Network > Wi-Fi > your network > DNS server assignment). Keep the loop running before,
   during and for a while after the change: a query reaching that address on the capture right after
   the change is the short gap until the helper rebuilds the filter (normally under 2 seconds); any
   query reaching it later is a leak.
4. Stop Throne while connected. The app should end with "could not reach the proxy" and the firewall
   should stay on; the lookups must still not appear on the capture. Start Throne and connect again.
5. Disconnect and reconnect from the app, and check the same while it connects.
6. Do this with the firewall in Automatic / Before Connection and in Always On.

Your router's web page, printers and file shares should keep working throughout.

## Building with GitHub Actions

1. In your fork on GitHub, open **Actions** and enable workflows (forks start with them disabled).
2. The workflow **Build Windows installer** runs on every push to `claude/adoring-fermi-qyxwb9`, or
   manually: Actions > Build Windows installer > Run workflow.
3. The first run takes a few hours: vcpkg builds Qt, OpenSSL, Boost and the rest from source. Those
   are cached, so later runs take much less. If the first run hits the time limit, run it again; it
   continues from the cache.
4. Download the installer from the finished run's **Artifacts** section (a zip containing
   `installer.exe`). Use it only from a run that is green all the way: after building, the workflow
   starts the packaged OpenVPN with the helper's proxy options to check they are accepted, then builds
   and runs the unit tests. The installer is uploaded before the tests run, so a red run can still
   have one; don't use it.

### Signed build (recommended)

The app's privileged helper service only accepts commands from a correctly signed app. To keep that
protection, sign the build with your own certificate.

**Create the certificate** (once, in PowerShell on your PC):

```powershell
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Windscribe Proxy Fork" `
  -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(5) `
  -TextExtension @("2.5.29.19={text}false") -CertStoreLocation Cert:\CurrentUser\My
```

```powershell
$password = -join (1..32 | ForEach-Object { [char]((48..57) + (65..90) + (97..122) | Get-Random) })
Export-PfxCertificate -Cert $cert -FilePath "$HOME\Desktop\ws-signing.pfx" -Password (ConvertTo-SecureString $password -AsPlainText -Force)
Export-Certificate -Cert $cert -FilePath "$HOME\Desktop\ws-signing.cer"
```

**Add two repository secrets** (GitHub: Settings > Secrets and variables > Actions > New repository secret):

- `WINDOWS_SIGNING_PFX_BASE64`: run this, then paste:
  ```powershell
  [Convert]::ToBase64String([IO.File]::ReadAllBytes("$HOME\Desktop\ws-signing.pfx")) | Set-Clipboard
  ```
- `WINDOWS_SIGNING_PFX_PASSWORD`: run this, then paste:
  ```powershell
  $password | Set-Clipboard
  ```

**Trust the certificate on the PC you install on** (PowerShell as Administrator):

```powershell
Import-Certificate -FilePath "$HOME\Desktop\ws-signing.cer" -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath "$HOME\Desktop\ws-signing.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

Then remove the private key from your PC; only GitHub needs it:

```powershell
Remove-Item "$HOME\Desktop\ws-signing.pfx"
Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)"
```

Anyone holding the private key could sign programs your PC would trust, so keep it only in the
GitHub secret. The certificate is limited to code signing and cannot issue other certificates.

### Dev-mode build (testing only)

Without the secrets the workflow builds in dev-mode: unsigned, with the signature and path checks
turned off. It works, but any program on your PC could then control the helper service, which runs
as SYSTEM. Use it to test, not for daily use.

## Installing

1. Uninstall the official Windscribe app (both use the same service and folders). Your account
   settings live on Windscribe's servers; log in again afterwards.
2. Run `installer.exe`. Windows SmartScreen may warn about an unknown publisher; choose
   More info > Run anyway.
3. Log in, then set up:
   - Preferences > Connection > Proxy Settings: HTTP, `127.0.0.1`, port `2080`.
   - Preferences > Connection > Connection Mode: Automatic or OpenVPN TCP.
   - Split Tunneling: Exclusive, with Throne and its core executables excluded.
   - Firewall: Before Connection or Always On if you want traffic blocked whenever the VPN is down.
     After a proxy or route error the firewall stays on; only your own Disconnect turns it off in
     Automatic mode.
   - Remove the three route lines from Advanced Parameters (see above).

**Updates.** A signed build rejects Windscribe's official updates (they are signed by Windscribe, not
by your certificate), so the app cannot replace itself with the official version. A dev-mode build
does not check, so decline update prompts there. To get Windscribe's fixes, merge their new stable
release into this branch and let the workflow build it.
