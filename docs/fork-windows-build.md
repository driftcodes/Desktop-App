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
- **Proxy on this PC (127.x.x.x).** The app replaces OpenVPN's `redirect-gateway` with the two routes
  `0.0.0.0/1` and `128.0.0.0/1` into the tunnel, for Windscribe servers and imported profiles. This is
  the fix you previously added in Advanced Parameters; you can remove these lines from there now:
  ```
  pull-filter ignore redirect-gateway
  route 0.0.0.0 128.0.0.0 vpn_gateway
  route 128.0.0.0 128.0.0.0 vpn_gateway
  ```
  (If you keep them, the app sees your own `pull-filter` line and leaves the config alone.)
  A profile containing `route-nopull`, `route-noexec` or its own `pull-filter ignore redirect-gateway`
  is also left alone.
- **`CONNECTED,ROUTE_ERROR`** from OpenVPN now ends the attempt with a clear message instead of an
  endless "Connecting".
- With the proxy off, everything behaves as in the official app.

Emergency Connect is unchanged and never uses the proxy.

## Building with GitHub Actions

1. In your fork on GitHub, open **Actions** and enable workflows (forks start with them disabled).
2. The workflow **Build Windows installer** runs on every push to `claude/adoring-fermi-qyxwb9`, or
   manually: Actions > Build Windows installer > Run workflow.
3. The first run takes a few hours: vcpkg builds Qt, OpenSSL, Boost and the rest from source. Those
   are cached, so later runs take much less. If the first run hits the time limit, run it again; it
   continues from the cache.
4. Download the installer from the finished run's **Artifacts** section (a zip containing
   `installer.exe`).

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
