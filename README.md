# Gakuen Idolmaster Launcher

A Windows and Linux launcher that runs Gakuen Idolmaster (DMM version) without requring DMM GAME PLAYER or an external VPN. The built-in VPN engines (OpenVPN and WireGuard) run entirely in user space, so no virtual network adapter or OS-level network configuration is needed.

Download `GakumasLauncher.exe` (Windows) or `GakumasLauncher-linux` (Linux; mark executable with `chmod +x`) from [Releases](../../releases) and run it. DMM GAME PLAYER does not need to be installed: the launcher handles login, the launch token, and game file downloads directly. Point **Settings → Game Folder → Change** at an existing installation, or at an **empty folder** to download the game files from scratch on first start.

## This fork's features

- English localization of the launcher
- Linux support, including DW-Proton installation, prefix dependency setup, bundled known-good DXVK for Vuplex-WebView support and the CrackProof kernel driver fix
- Built-in **English Localization (Localify)** installer and updater, with automatic English translation configuration on non-Chinese systems
- Launcher and Localify self-updater
- Built-in **DMM Browser**, in-app **Register** flow, automatic first-launch DMM account setup, and fresh game downloads into an empty folder without ever installing DMM GAME PLAYER
- Custom game executable override

## Japan connection methods

Select a connection method in the **Japan Connection** panel:

| Method                | Description                                                                                                                                                                                                                                                                                                                                          |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **VPN Gate**          | Default. Connects from within the launcher to Japanese VPN Gate public servers — racing diverse Japanese relays (TCP and UDP) across distinct `/24` subnets ranked by speed, ping, uptime and score, verifying each tunnel's data plane before use, remembering the last working server and temporarily cooling down failed or DMM-rejected servers/subnets, and falling back to built-in University of Tsukuba profiles if the list is unreachable. No setup required. |
| **VPN File**          | Connects from within the launcher using a manual configuration file from your VPN service. Supports OpenVPN (`.ovpn`) and WireGuard (`.conf`).                                                                                                                                                                                                       |
| **Direct Connection** | Uses your PC's internet connection as-is, without a launcher VPN. If you are outside Japan, connect to Japan with a VPN app first.                                                                                                                                                                                                                   |

**VPN Gate** and **VPN File** do not modify Windows or Linux network settings: only the launcher's region-checked DMM API requests and in-app **Browser** traffic go through the VPN. Game file downloads always use your normal internet connection.

### How to use a VPN file

1. Download the manual configuration file (OpenVPN `.ovpn` or WireGuard `.conf`) for a **Japanese server** from your VPN service's account page.
2. In the **Japan Connection** panel, select **VPN File** → **Choose File** and pick the file you downloaded. External OpenVPN certificate, key, or credential files referenced in the same folder are imported automatically.
3. If the OpenVPN file requires a username and password, enter them in **Account**. This is often a manual-setup (OpenVPN) credential rather than your VPN service's website login.

The configuration file and credentials are stored encrypted on your machine.

## Localization (Localify)

The **Localization (Localify)** panel downloads the latest `DMM_GakumasLocalify_v*.zip` from [gakuen-imas-localify](https://github.com/chinosk6/gakuen-imas-localify) and installs it next to `gakumas.exe`:

- **First install** (no `gakumas-local/` folder yet): Extracts `version.dll` and `gakumas-local/`. Unless your system language is Chinese, it omits the bundled Chinese `local-files`, sets `replaceFont` to `false` in `localizationConfig.json`, and in `config.json` sets `useAPITextureAssets` to `false`, `useAPIAssets` to `true`, and `useAPIAssetsURL` to the [English translation data](https://github.com/NatsumeLS/Gakumas-Translation-Data-EN).
- **Updates and reinstalls:** When `gakumas-local/` already exists, installing or updating replaces only `version.dll` and leaves your existing localization files alone. (Delete `gakumas-local/` first if you want a clean config reinstall.)
- **Verification and version tracking:** Downloads are verified against the release's SHA-256 digest, and only the newest archive is kept in the cache. The launcher records the installed tag and the SHA-256 of `version.dll`, displays whether Localify is installed and which version, and compares releases as semver so an older tag is never offered as an update. A `version.dll` the launcher did not install (or one modified externally) counts as an unknown version, and the latest release is offered for it.
- Installing or updating is refused while the game is running. 

## Account, Browser, and Settings

### DMM Account and Browser

- **Login** and **Register** always use your system connection, even when a launcher VPN is selected - they don't require a Japanese IP.
- **Login** opens an in-app WebView window. On Windows, WebView2's own password save and autofill are enabled, and DMM's "keep logged in" box is pre-checked unless you uncheck it. The launcher never reads your password.
- **Register** opens DMM's account signup page in an in-app window. When you close it (if not already logged in), the launcher automatically reuses that browser session to sign in.
- **Logout** clears both the saved login token and the WebView's stored DMM session and saved passwords.
- **Automatic first-launch account setup:** When launching with a new DMM account, the launcher automatically confirms game terms, adds Gakumas to **My Games**, and attempts background DMM GAMES profile setup using the current run's login session. If DMM still reports that profile registration is required, open **Browser** to finish setting up your account and try again.
- **Browser** opens DMM with a built-in navigation bar (Back, Forward, and URL bar) and routes HTTPS through the selected launcher VPN in a separate private (incognito) session (resolving DMM domains inside the tunnel), or uses your system connection in **Direct Connection** mode. Close the browser before changing VPN settings or logging out. If a VPN connection drops, reload the page after the launcher reconnects.

### Settings and game updates

- **Start automatically on launch:** Starts the game immediately when the launcher opens (once a game folder is configured).
- **Exit launcher after starting the game:** Closes the launcher automatically once the game launches.
- **Game Folder:** Auto-detected from DMM GAME PLAYER if an existing installation is found (on Windows, or inside a configured Proton prefix on Linux). Use **Change** to pick an existing installation or an empty folder. On launch, the launcher checks DMM's update manifest over your normal connection, downloads only missing or changed files (verified by size and MD5), and deletes obsolete files. Updates containing DMM-protected files cannot be downloaded by the launcher and require DMM GAME PLAYER.
- **Executable override:** If you want to run a different or patched executable instead of the one returned by DMM, use **Settings → Executable override → Choose**. Relative paths are resolved inside the game folder; absolute paths are used as-is. **Reset** returns to the default. The game folder must still be set.
- **Log:** Click the log button in the bottom-left corner to view or copy timestamped session logs. Attempting to close the launcher while an operation is running prompts for confirmation.

## Updates

### Launcher self-update

The **Launcher update** panel shows the running version and the newest stable release from [the fork's GitHub releases](https://github.com/Portalboy07/gakumas-launcher-fork/releases) that ships a binary for your platform (`GakumasLauncher.exe` or `GakumasLauncher-linux`). Prereleases are offered only to prerelease builds.

Clicking **Update launcher** downloads the platform binary, verifies its SHA-256 digest and executable header, replaces the running executable, and offers to restart (if postponed, the button switches to **Restart to update**). Every build, including forks' builds, updates from this repository's releases. Local builds show `Cargo.toml`'s version, can check for updates, and do not replace themselves.

### Automatic and manual update checks

- On launch, the launcher and Localify are checked together at most once every 24 hours. Localify is looked up during the daily check only while it is installed.
- If a lookup fails, the other component's result is still saved and the daily check runs again on the next launch.
- Each panel's **Check for updates** button checks only that panel's component immediately without resetting the 24-hour daily timer.
- When a check finds an update that can be installed, a popup lists it and asks whether to install now (**Later** skips it until the next check). The popup waits until no other task or popup is open, installs Localify before the launcher, and offers to restart after a launcher update.

## Linux / Proton

The Linux build runs the Windows game through [DW-Proton](https://github.com/dawn-winery/dwproton-mirror), which is required for the CrackProof anti-debug driver fix.

### Requirements

- `winetricks` installed and available in `PATH` (for prefix dependency setup)
- `tar` with `xz` support (for extracting DW-Proton)
- Host GStreamer H.264 plugins (such as `gst-plugins-ugly` / `gst-libav`, depending on your distribution) for in-game video playback

### Setup

1. Make the binary executable (`chmod +x GakumasLauncher-linux`) and launch it.
2. In the **Proton (Linux)** panel, click **Install DW-Proton** to download and extract the latest DW-Proton release into Steam's `compatibilitytools.d` (if a DW-Proton version is already installed there, the button selects the newest installed one without downloading again), or pick an already installed tool from the dropdown (listed newest name first). To use a custom Proton directory (or its `proton` script) or a custom Wine prefix path, enter the path and click **Apply**. Both the Proton version and prefix path are remembered in settings.
3. Click **Create prefix & install dependencies**. This creates the 64-bit prefix with `wineboot`, installs `corefonts`, `powershell`, `vcrun2022`, and `webview2` using `winetricks` from your `PATH` and the selected Proton (no Heroic or protontricks needed; WebView2 falls back to Microsoft's bootstrapper if your `winetricks` lacks that verb), sets up fallback fonts (`msyh.ttc`, `segoeui.ttf`) for the Localify menu, and installs the bundled DXVK DLLs if a game folder is already selected.
4. Use **Settings → Game Folder → Change** to point at an existing game folder or an empty folder to download the game from scratch. Use **Executable override** if you need a different executable.
5. Log in and start the game as usual.

### Driver fix, DXVK, and persistent game data

- **Anti-debug driver and launch environment:** Before launching, the launcher downloads and SHA-256-verifies `usrdrv017764.sys`, installs it into the prefix, and registers and starts its service in the **same Wine session** as the game via a generated CMD script. Because Wine's `NtLoadDriver` is a stub, preloading the service this way lets the original executable start. `WINE_SERVICES_SESSION0=1`, `WINEDLLOVERRIDES=version.dll=n,b;winmm=b;d3d11=n;dxgi=n`, and host `GST_PLUGIN_PATH_1_0` plugin directories are configured automatically. This approach is based on [0nikod/gakumas-proton](https://github.com/0nikod/gakumas-proton).
- **Bundled DXVK:** The launcher bundles the DXVK D3D11/DXGI build from [GE-Proton10-31](https://github.com/GloriousEggroll/proton-ge-custom/releases/tag/GE-Proton10-31) rather than an upstream release — that exact build is needed for the in-game Vuplex webview. On every launch (and during prefix setup if a game folder is set), the DLLs are verified and written into both the game folder and `gakumas_Data/Plugins/x86_64/VuplexWebViewChromium`. See [assets/dxvk/SOURCE.md](assets/dxvk/SOURCE.md) for hashes and provenance.
- **Persistent game app-data:** The game stores the index of its ~7 GB asset cache in `AppData/LocalLow/BANDAI NAMCO Entertainment Inc_` inside the prefix, so a new prefix would otherwise make it re-download that cache. When the prefix is created and before every launch, the launcher moves this folder to `game-appdata/` in its own data folder and leaves a symlink in the prefix — so deleting or recreating the prefix keeps the data (deleting the launcher's data folder does not). Nothing is deleted during migration:
  - If both places already hold data, they are merged with the newer copy of each file winning, and the prefix's old folder is kept beside the link as `BANDAI NAMCO Entertainment Inc_.prefix-backup` (`-2`, `-3`, … for later ones).
  - If an existing symlink pointed elsewhere, that folder's contents are copied in and the old link is kept as `BANDAI NAMCO Entertainment Inc_.wrong-link`.
  - If the move fails, the game still launches with its data inside the prefix.

## Data folder

Settings, encrypted credentials, cached downloads, and (on Linux) the default Proton prefix and `game-appdata/` are stored in the launcher's app-local-data folder:

- **Windows:** `%LOCALAPPDATA%\local.gakumas.launcher`
- **Linux:** `~/.local/share/local.gakumas.launcher` (or `$XDG_DATA_HOME/local.gakumas.launcher`)

## Building

On Linux (Debian/Ubuntu), install the Tauri GTK 3 / WebKit2GTK 4.1 development packages first:

```sh
sudo apt-get install -y \
  libwebkit2gtk-4.1-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  patchelf
```

Then build the release binary:

```sh
cargo build --release --bin GakumasLauncher
```

The binary is written to `target/release/GakumasLauncher.exe` on Windows or `target/release/GakumasLauncher` on Linux.

The GitHub release workflow passes the tag's version to the compiler through `LAUNCHER_VERSION` so `Cargo.toml` and `Cargo.lock` are not modified and CI builds stay `--locked`.

## Note

DMM does not support use from outside Japan. Automating the login requests and utilizing the English Patch is against DMM TOS. There were no confirmed bans yet, but that doesn't mean there can't be. You are responsible for any consequences of using this launcher.
