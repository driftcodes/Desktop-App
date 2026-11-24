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
  app). That permits traffic to it but does not send any.

### Firewall behaviour

In Automatic mode the firewall only stays on after connecting when the tunnel carries all IPv4 traffic.
The app now decides this the way OpenVPN does, from the profile and everything the server pushed: the
profile's own `redirect-gateway`, its own `0.0.0.0/1` + `128.0.0.0/1` routes, or a pushed
`redirect-gateway` (with or without `def1`) or pushed `/1` routes that the profile does not drop with
`route-nopull` or a matching `pull-filter` (a case-sensitive prefix match, quotes included). A
`redirect-gateway` carrying `!ipv4`, pushed or not, means IPv4 is not redirected. Routes count when they go through
the tunnel (`vpn_gateway`, `default`, no gateway, the pushed `route-gateway`, the `ifconfig` peer, or an
address on the tunnel's subnet), and together they must cover all IPv4 addresses (two `/1`s, four
`/2`s, `0.0.0.0/0`, or any other split). Only lines that actually reach OpenVPN count: the
helper strips `route-noexec` and `redirect-private` from imported files, so they are ignored here too.
The decision is made once connected, from the profile and the server's push together. Before,
an imported profile with `pull-filter ignore redirect-gateway` (even with its own full routes), or one
whose `redirect-gateway` was in the file rather than pushed by the server, made Automatic / Before
Connection switch the firewall off once connected. A profile that really only routes some networks
still switches it off, because blocking everything else would cut your internet. **Always On** never
switches the firewall off.

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
