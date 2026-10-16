# duckJump Assist (desktop app)

The app end users open to get attended remote support. It signs in to the
gateway, requests a support session (or joins a technician's invitation),
shows the verification code, and shares the screen in-process once the
technician has entered that code. Built with Tauri 2; the window is static
HTML/JS in `ui/`, with no Node toolchain.

- **Sign-in**: gateway username and password (with the TOTP step when the
  account has one) or single sign-on. A support request needs a signed-in
  user: the gateway refuses anonymous ones.
- **Single sign-on** follows RFC 8252. The app listens on
  `127.0.0.1:<random port>`, opens the browser at
  `/api/v1/auth/oidc/login?redirect_uri=…&state=…&code_challenge=…`, and
  redeems the one-time code it gets back at `POST /api/v1/auth/oidc/token`
  with its PKCE verifier. The session token never appears in a URL.
- **"Active Directory"** only prefills `DOMAIN\user` from the workstation
  (USERDOMAIN on Windows; `user@realm`, winbind or Kerberos with SSSD on
  Linux), and the request is recorded under that name. The password is
  checked by the gateway, which has no LDAP: for real AD accounts, put AD
  behind the identity provider (Entra ID, Keycloak user federation) and use
  single sign-on.
- **Stopping**: the red button, closing the window, or the technician ending
  it. The first two also tell the gateway (`POST /api/v1/support/end/{token}`).

## How users get it

The technician's link (`/support/join/<token>`) serves both cases:

- **App installed**: "Abrir en duckJump Assist" opens
  `duckjump-assist://join?server=…&token=…`. Any web page can open such a
  link, so the app shows the server and asks the user to allow it before
  connecting; the verification code is still required. A second launch hands
  the link to the running app (single instance).
- **No app**: the one-line launchers (`launch.sh`, `run.ps1`) or the download
  run the `duckjump-assist` CLI from a temporary directory, nothing installed.
  They always use this gateway and its binary, whatever the query says.
- When installers are in `dist/bin` (`make assist-app-bundle`), the page also
  offers them (`/support/duckjump-assist-app?os=linux|windows`) for next time.

The logic lives in crates that build and test without WebKit:
`duckjump-assist` (the session: capture, input, gateway channels) and
`duckjump-assist-client` (gateway API, single sign-on, identity, invitation
links). This crate is only the window and its commands.

## Build

Linux needs WebKitGTK:

```sh
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev libxdo-dev
make assist-app                      # or: cd duckjumpd/assist-app && cargo build --release
```

Installers (deb, AppImage; MSI and NSIS on Windows) come from the Tauri CLI:

```sh
cargo install tauri-cli --version '^2' --locked
cd duckjumpd/assist-app && cargo tauri build
```

`RUST_LOG=debug` adds the streaming statistics to the log.
