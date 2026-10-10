# ESP32-C6-AdBlock

A **Pi-hole-style DNS ad-blocker** for ESP32-C6-WROOM boards — *no PSRAM required*.

> **Origin:** This project adapts M-Abozaid's DNS ad-blocking project for ESP32-C6. See [Credits](#credits) for attribution.

The trick everyone misses: you don't need to keep the blocklist in RAM. Store the
domains as **sorted 40-bit hashes in flash** and binary-search them. 140,000+ domains
fit in ~0.7 MB of flash. The ESP32-C6 build uses a flash index sized for up to about
2.08 million domain hashes; RAM use stays independent of blocklist size.

```
query in ──▶ extract domain ──▶ FNV-1a hash (+ parent suffixes)
         ──▶ binary-search the flash hash table
              ├─ hit  ──▶ answer 0.0.0.0   (sinkholed)
              └─ miss ──▶ forward to upstream resolver, relay the reply
```

Upstream forwarding is non-blocking (up to 32 requests in flight). Successful
answers are cached for their DNS TTL, capped at five minutes; blocklist checks
still run before cache lookups.

## Why this is interesting

The ESP32-C6 can store fixed **5-byte (40-bit) hashes in flash**, so the blocklist
does not need to be loaded into RAM:

| Metric | ESP32-C6 |
|---|---|---|
| Hardware | ESP32-C6-WROOM, no PSRAM |
| 141k domains | **0.67 MB of flash** |
| RAM used | fixed buffers, independent of blocklist size |
| Lookup | ~18 flash reads (~10 ms incl. WiFi RTT) |
| Collisions | 0 at 141k (1 at 537k) |

**Why 40 bits?** It's the sweet spot for this flash budget. Collisions follow the
birthday bound — at 141k domains you get ~0, at 537k about 1 (i.e. one unlucky
domain gets over-blocked). Dropping to 32 bits would save 20% of the flash but
cost ~7 collisions at 250k; going to 64 bits wastes 3 bytes per domain to solve
a problem you don't have.

The 16 MB ESP32-C6 module uses an 8,192-entry flash index that can address up to
**~2.08M domains** without loading the full blocklist into RAM.

## Hardware

- **ESP32-C6-WROOM** on a carrier board or ESP32-C6-DevKitC-1; the primary target uses 16 MB flash.
- An 8 MB ESP32-C6 module can use the `c6_8mb` environment.
- No PSRAM is required. The BOOT button on the ESP32-C6-DevKitC-1 uses GPIO9.
- Power it from a **stable USB source** (a phone charger or your router's USB port).
  Cheap/loose USB-C→A adapters can brown out the radio during WiFi transmit.
- Keep the module antenna clear of metal and enclosure walls to preserve WiFi signal.

## Build & flash (PlatformIO)

One USB flash to get going — after that, **firmware and blocklist both update over WiFi** (see below).

> Use a current PlatformIO release. The C6 target uses the pioarduino platform for
> Arduino core 3.x support. A browser installer is available for the 16 MB build.

```bash
# 1. Keep your existing src/secrets.h. If it does not exist yet, create it from
#    the template and set WEB_USER / WEB_PASS / OTA_PASS before flashing.
#    WIFI_SSID / WIFI_PASS can be left as placeholders if you will use the
#    on-device setup portal instead.
test -f src/secrets.h || cp src/secrets.example.h src/secrets.h

# 2. build the blocklist hash table (default = StevenBlack base + Hagezi Light,
#    ~100k entries, WhatsApp/social safe)
python3 tools/build_blocklist.py data/blocklist.bin

# 3. flash firmware + the blocklist filesystem (the one and only USB flash)
pio run -t upload
pio run -t uploadfs

# 4. watch it boot, note the IP / open the dashboard
pio device monitor          # -> http://c6adblock.local
```

### Flash size and partitions

The default `c6` environment targets the 16 MB ESP32-C6-WROOM, with two 2.5 MB
OTA app slots and the remaining flash for LittleFS. The `c6_8mb` environment uses
the matching 8 MB partition layout. Both retain firmware OTA.

```bash
pio run -e c6 -t upload
pio run -e c6 -t uploadfs
pio device monitor -e c6
```

Use `-e c6_8mb` in these commands for an 8 MB module.

On a custom carrier board, check that its BOOT button is wired to GPIO9 before
using it to clear saved WiFi settings.

### Your own blocklists

`build_blocklist.py OUT.bin [SOURCE ...]` takes any mix of URLs and local files, in any of
these formats:

- **hosts files** — `0.0.0.0 ads.example.com tracker.example.com` (all domains on the line are included)
- **plain domain lists** — one domain per line
- **AdGuard / Adblock basic rules** — `||ads.example.com^` blocks, `@@||ok.example.com^`
  removes a domain (e.g. to mirror an AdGuard Home allowlist)

A blocked domain also blocks its subdomains. Rules a DNS hash list can't express (regex,
wildcards, `$` modifiers, cosmetic `##` rules) are skipped and counted. An `@@` rule only
un-blocks that exact entry — it can't carve a subdomain out of a blocked parent. If a source
can't be downloaded the build stops instead of silently producing a smaller list
(`--allow-missing` to override).

### WiFi setup (no re-flash needed)

If it can't connect (or you never set `secrets.h`), it starts an open access point
**`C6-AdBlock-XXXX`** with a captive
portal — join it from a phone, pick your network, type the password, done. To
move it to a new network later: click **Forget WiFi** on
the dashboard, or hold the **BOOT** button while powering on, and the setup portal
comes back. (`/forgetwifi` requires auth now, so it's no longer a bare URL you can
just visit — see Security below.)

## Over-the-air updates (no more USB)

The dashboard at **http://c6adblock.local** does it all:

- **Blocklist** — drop a freshly built `blocklist.bin` into *Blocklist → Upload*, or set a
  URL under *Remote auto-update* and the device pulls a prebuilt `blocklist.bin`
  on a schedule. A fresh default list is rebuilt **every Monday** by GitHub Actions and
  published at a stable URL, so pasting this once keeps a device current on its own:
  `https://github.com/M-Abozaid/esp32-c6-adblock/releases/download/blocklist/blocklist.bin`
- **Firmware** — upload `.pio/build/<environment>/firmware.bin` under *Firmware → OTA update*;
  use `c6` for ESP32-C6. The device verifies it and reboots into the new image. Or push over WiFi from the CLI:
  ```bash
  pio run -e c6 -t upload --upload-port c6adblock.local --upload-protocol espota
  ```
  Use `-e c6_8mb` for an 8 MB module.

The dashboard shows recent blocked domains and client IPs. The device keeps a
12-event ring buffer in RAM; the browser can save up to 200 received events in
its localStorage. This log does not write to device flash.

The 16 MB layout reserves about 10.9 MiB for LittleFS; the 8 MB layout reserves
about 3 MiB. The blocklist index supports up to ~2.08M domains, subject to the
filesystem space available on the selected module.

## Security

The dashboard's read-only view (`/`, `/stats.json`, `/events.json`) stays open, but every
state-changing endpoint requires **HTTP Basic Auth** (`WEB_USER`/`WEB_PASS` from
`secrets.h`):

- `/ban`, `/addblock`, `/unblock`, `/forgetwifi`
- `/upload`, `/update` (blocklist and firmware OTA)
- `/setupdate`, `/fetchnow`

Network OTA (`ArduinoOTA`, e.g. `pio run -e c6 -t upload --upload-port c6adblock.local
--upload-protocol espota`) requires `OTA_PASS` from the same file.

Without this, anyone who could reach the device on the LAN could reflash it
with arbitrary firmware or rewrite the blocklist with zero credentials — worth
knowing given the device sits in the path of every DNS query on your network.
Custom blocked-domain names are also HTML-escaped before being rendered on the
dashboard, closing a stored-XSS path where a domain string containing markup
(added via `/addblock`) would otherwise execute in the viewing browser.

**Basic Auth here is a LAN-trust-boundary control, not encryption.** Everything
is plain HTTP on :80 — this chip has no realistic budget to run a TLS server.
Basic Auth credentials are base64 (not encrypted) and sent on every authenticated
request; anyone who can already sniff your LAN traffic (open/guest WiFi, ARP
spoofing) can read them off the wire. This hardens against the common case —
another device on your network hitting the API with no credentials at all, or a
browser tab CSRF'ing it — not against an on-path network attacker.

**CSRF via cached Basic Auth:** browsers auto-attach cached Basic Auth
credentials to *any* subsequent request to an already-authenticated origin —
including one triggered by a totally unrelated page the same browser visits
later (e.g. `<img src="http://c6adblock.local/forgetwifi">`, no JS required).
That would let any webpage silently drive this API once you've logged into the
dashboard once, regardless of who's on your LAN. Every mutating endpoint above
now also requires a custom `X-Requested-With: c6-adblock` header, which a plain
`<img>`/auto-submitted `<form>` CSRF can't attach (only same-origin `fetch()`
can, which is what the dashboard's own JS does) — this is why `/forgetwifi` is
no longer a bare URL you can visit directly; use the dashboard button instead.

**Default credentials:** if `secrets.h` still has the placeholder
`CHANGE_ME_WEB_PASSWORD` / `CHANGE_ME_OTA_PASSWORD` values from
`secrets.example.h`, the device boots with a "password" that's public (it's
sitting in this repo's example file). The firmware logs a warning over serial
and shows a banner on the dashboard when this is the case — but it will still
boot and run, so don't skip setting real values in `secrets.h` before trusting
this on a network you don't fully control.

Out of scope for now: the WiFi setup portal's access point (`C6-AdBlock-XXXX`)
is still open (unencrypted) by design — it needs to be joinable without knowing
a password first. The real WiFi password you type into the portal is only as
safe as that local radio link during the brief setup window.

## Use it

Point a device's DNS at the C6's IP, or add it as a **secondary resolver** behind
your main DNS. Test:

```bash
dig @<c6-ip> doubleclick.net   # -> 0.0.0.0  (blocked)
dig @<c6-ip> github.com        # -> real IP  (forwarded)
```

## Gotchas (learned the hard way)

- **ModemManager** (default on Fedora/Ubuntu) grabs `/dev/ttyACM0` and toggles
  DTR/RTS, which can **reset the C6** and block serial. Fix:
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```
- The C6's USB-Serial-JTAG console can swallow early boot output until the host
  connects (`while(!Serial)` helps).
- DNS clients add an **EDNS OPT** record; a blocked reply must contain only the
  question + answer (ANCOUNT=1, NSCOUNT=ARCOUNT=0) or it's malformed.

## Done / how it could grow

- ✅ Web dashboard — per-client block/allow counts, ban a client, add custom domains
- ✅ mDNS (`c6adblock.local`) for discovery
- ✅ OTA — firmware + blocklist update over WiFi, plus scheduled remote blocklist pulls
- ✅ Captive-portal WiFi setup (no hardcoded creds) + one-click browser web-installer
- ⬜ Bucketed prefix index — ~18 flash reads/lookup → ~1–2 (issue #3), the throughput win
- ⬜ Act as the DHCP server (hand itself out as DNS) for true plug-and-play

## Credits

This project adapts M-Abozaid's DNS ad-blocking project for ESP32-C6, with a 16 MB default target and an optional 8 MB build configuration. The hardware requirements, partition layouts, setup steps, and firmware behavior described above apply to ESP32-C6 only.

The DNS response approach for answering blocked queries with `0.0.0.0` was inspired by s60sc's AdBlocker project; that attribution is retained here.

## License

This adaptation is distributed under the MIT License. The upstream copyright notice and MIT license text are retained in [LICENSE](LICENSE); keep those notices with copies or substantial portions of the software.
