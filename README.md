# Gakuen Idolmaster Launcher

A Windows and Linux launcher that runs Gakuen Idolmaster (DMM version) without DMM GAME PLAYER or a VPN. The built-in VPN engines are user space, so no OS-level VPN or network configuration is needed.

Download `GakumasLauncher.exe` from [Releases](../../releases) and run it. DMM GAME PLAYER does not need to be installed: the launcher handles login, the launch token, and the game file downloads directly. Point **Game folder → Change** at an existing installation, or at an **empty folder** — the launcher will download the game files from scratch on first start.

## This fork's features

- English localization of the launcher
- Proton configuration features, including the anti-debug driver fix
- Localify installer

## Japan connection methods

| Method | Description |
|---|---|
| VPN Gate | Default. Connects to the University of Tsukuba's VPN Gate public server only from within the launcher. No additional setup required. |
| VPN file | Connects from within the launcher using a configuration file from your VPN service. Supports OpenVPN (`.ovpn`) and WireGuard (`.conf`). |
| Direct connection | Uses this PC's internet connection as-is, without a VPN. If you are outside Japan, connect to Japan with a VPN app first. |

VPN Gate and VPN file do not change Windows network settings; only the launcher's traffic goes through the VPN.

**Login** and **Register** use your system connection, even when a launcher VPN is selected. **Browser** routes HTTPS through the selected launcher VPN in a separate private session, or uses your system connection in Direct mode. Close the browser before changing VPN settings. If a VPN Gate connection drops, reload the page after the launcher reconnects.

### How to use a VPN file

1. Download the manual configuration file (OpenVPN or WireGuard) for a **Japanese server** from your VPN service's account page.
2. In the launcher, choose **VPN File** → **Choose File** and select the file you downloaded.
3. If the OpenVPN file requires a username and password, enter them in **Account**. This is often a manual-setup (OpenVPN) account rather than your service login password.

The configuration file and account are stored encrypted so that they can only be decrypted by this PC's Windows account.

## Custom game executable

If the game executable has been patched (for example, a Proton-tuned build with protection checks disabled), use **Settings → Executable override → Choose** to select it. The chosen path is used instead of the executable name returned by DMM. Relative paths are resolved inside the game folder; absolute paths are used as-is. **Reset** returns to the default. The game folder must still be set.

## Linux / Proton

The Linux build runs the Windows game through a user-selected Proton version.

1. In the **Proton (Linux)** panel, click **Install DW-Proton** to download and extract the latest DW-Proton release into Steam's `compatibilitytools.d`, or select an already installed Proton from the list. DW-Proton is required for the original executable (it handles the CrackProof anti-debug driver); a pre-unpacked executable works with other Proton builds too.
2. Click **Create prefix & install dependencies**. This creates the prefix with `wineboot` and installs `corefonts`, `powershell`, `webview2` and `vcrun2022`. It uses the `winetricks` from your `PATH` and the Proton you selected (no Heroic or protontricks needed); WebView2 is installed from Microsoft's bootstrapper if your winetricks lacks that verb.
3. Use **Game folder → Change** to point at the folder containing `gakumas.exe` (auto-detection from DMM GAME PLAYER only works on Windows). Use **Executable override** to choose a different executable.
4. Log in and start the game as usual.

The **Localization (Localify)** panel downloads the latest `DMM_GakumasLocalify_v*.zip` from [gakuen-imas-localify](https://github.com/chinosk6/gakuen-imas-localify) and installs it next to `gakumas.exe`. On a first install (no `gakumas-local` folder yet) it extracts `version.dll` and `gakumas-local/`. Unless the system language is Chinese, it leaves out the bundled Chinese `local-files`, sets `replaceFont` to `false` in `localizationConfig.json`, and in `config.json` sets `useAPITextureAssets` to `false`, `useAPIAssets` to `true`, and `useAPIAssetsURL` to the [English translation data](https://github.com/NatsumeLS/Gakumas-Translation-Data-EN). An update replaces only `version.dll` and leaves existing localization files alone. The download is checked against the release's SHA-256 digest, and only the newest archive is kept in the cache. The launcher records the installed tag and the SHA-256 of `version.dll`, shows whether Localify is installed and which version, and checks for a newer release at most once every 24 hours on launch (or on demand with **Check for updates**).

Before launching, the launcher downloads and verifies the anti-debug driver (`usrdrv017764.sys`), installs it into the prefix, and registers/starts its service in the **same Wine session** as the game via a generated CMD script. Wine's `NtLoadDriver` is a stub, so doing this beforehand is what lets the original executable run. `WINE_SERVICES_SESSION0=1` and `version.dll=n,b` (native then builtin, for localization mods) are set automatically.

The Proton version and prefix are remembered in the launcher's settings.

The Linux driver-fix approach is based on [0nikod/gakumas-proton](https://github.com/0nikod/gakumas-proton), which documents preloading the `usrdrv017764.sys` anti-debug driver service in the same Wine session so the original executable can start.

## Build

On Linux, Tauri needs the GTK 3 / WebKit2GTK 4.1 development packages installed first.

```
cargo build --release --bin GakumasLauncher
```

The binary is written to `target/release/GakumasLauncher`.

## Note

DMM does not support use from outside Japan. You are responsible for any consequences of using this launcher.
