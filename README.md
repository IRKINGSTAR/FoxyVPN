# FoxyVPN — Unofficial Mozilla VPN client for Windows & Android

<div dir="rtl">

کلاینت غیررسمی سرویس <b>Mozilla Firefox VPN</b> برای ویندوز و اندروید.
با حساب فایرفاکسِ دارای اشتراک Mozilla VPN وارد شوید و از تانل MASQUE روی شبکه‌ی لبه‌ی Fastly استفاده کنید.

</div>

A modern, privacy-focused client for Mozilla's Firefox VPN service — powered by a customized sing-box core (MASQUE over Fastly edge, HTTP/1.1 · HTTP/2 · HTTP/3).

## Downloads / دانلود

Latest release: **[Releases](../../releases)**

| Package | Platform | Size |
|---|---|---|
| `FoxyVPN-Portable-v2.0.3-win-x64.zip` | Windows 10/11 x64 — portable, no install | ~16 MB |
| `FoxyVPN-Android-v2.0.2.zip` | Android 8.0+ — 3 signed APKs (universal / arm64 / armv7) | ~98 MB |

<div dir="rtl">

دوستان عزیز: برای ویندوز، zip را باز کنید و روی <b>FoxyVPN.exe</b> دوبار کلیک کنید (بدون نصب). برای اندروید،
<span dir="ltr"><b>app-universal-release.apk</b></span> را نصب کنید (اجازه‌ی نصب برنامه‌ی ناشناس را بدهید) و با حساب فایرفاکسِ
داشتن اشتراک Mozilla VPN وارد شوید. امضای هر دو پکیج شخصی است؛ هشدار امنیتی اولیه را با «نصب با این روش» رد کنید.

</div>

## Features

- **VPN tunnel (TUN)** — system-wide, wintun on Windows / VpnService on Android, leak-proof DNS (chained DoH, DoT blocked)
- **Proxy-only mode** — local SOCKS5/HTTP listener (`127.0.0.1:1080`), optional Windows system-proxy integration
- **Region picker** — live server directory from Mozilla Remote Settings (34 countries), real SVG flags
- **Per-app split tunneling** — by process name on Windows, by package on Android
- **Short-lived JWT** auto-rotation before expiry (`dynamic_bearer_token` sing-box fork), quota display
- **Fastly anti-bot challenge solver** (PoW / PAT / client-metrics) + uTLS Firefox fingerprint on the control plane
- **Bounded auto-recovery** — server switch within the selected country after confirmed proxy-path failure
- Multi-HTTP-version (1/2/3), uTLS fingerprints, TLS fragmentation, custom edge, upstream proxy, DoH bootstrap
- Persian (RTL) / English UI, dark & light themes, system tray, quick-connect

## Sign in

Use your Firefox account that has an active **Mozilla VPN** subscription. Access, quota and geo-availability are controlled by Mozilla — this client talks to the official endpoints and respects account quotas.

## Building

### Windows
- Go ≥ 1.25, Node ≥ 18, WebView2 Runtime (preinstalled on Win10/11)
- `git clone --depth 1 --branch foxy-masque https://github.com/Vauth/sing-box.git libs/sing-box`
- `go mod tidy` then `build.bat` → `build\FoxyVPN-Portable.exe` (wintun.dll is embedded)

### Android
- JDK 17, Android SDK (build-tools 35), Gradle 8.10.2
- `curl -L -o app/libs/libbox.aar https://github.com/Vauth/sing-box/releases/download/v1.0.0-masque/libbox.aar` (sha256 pinned in README of the upstream)
- `gradle :app:assembleRelease`

## Credits / Acknowledgements

- [Vauth/FoxyVPN](https://github.com/Vauth/FoxyVPN) — the Android app this project is based on (MIT)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) + Vauth's MASQUE fork — tunnel core
- [UjuiUjuMandan/firefox-vpn-client](https://github.com/UjuiUjuMandan/firefox-vpn-client) — Go reference client
- [Hatscripts/circle-flags](https://github.com/Hatscripts/circle-flags) & [lipis/flag-icons](https://github.com/lipis/flag-icons) — flags
- [Vazirmatn](https://github.com/rastikerdar/vazirmatn) — Persian font

## License

MIT — see [LICENSE](LICENSE).

<div dir="rtl">

⚠️ این پروژه به اندپوینت‌های مستندنشده‌ی موزیلا وصل می‌شود؛ تغییر سیاست موزیلا ممکن است نیاز به به‌روزرسانی داشته باشد. مسئولیت استفاده با کاربر است.

</div>
