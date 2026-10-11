// ESP32 AdBlock — DNS sinkhole + web dashboard (no PSRAM required).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, looked up through a RAM prefix directory.
// Dashboard at http://c6adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <AsyncUDP.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <freertos/semphr.h>
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include <time.h>
#include "esp32-hal-rgb-led.h" // addressable RGB LED on the ESP32-C6-DevKitC-1
#include "esp_netif.h"         // AP DHCP DNS + NAPT routing
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

#ifndef C6_AP_PASSWORD
#define C6_AP_PASSWORD "CHANGE_ME_AP_PASSWORD"
#endif
static_assert(sizeof(C6_AP_PASSWORD) >= 9, "C6_AP_PASSWORD must be at least 8 characters");

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const char* BLOCKLIST_TEMP_PATH = "/blocklist.new";
static const char* BLOCKLIST_BACKUP_PATH = "/blocklist.old";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const uint32_t PREFIX_BITS = 14;
static const uint32_t PREFIX_BUCKETS = 1UL << PREFIX_BITS;
static const uint32_t PREFIX_SHIFT = HASH_BYTES * 8 - PREFIX_BITS;
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket
// Keep the previous supported-list limit; dense prefix buckets use a safe binary-search fallback.
static const uint32_t MAX_INDEXED_HASHES = (8192UL - 1) * (MAX_RANGE - 1) + 1;
static const int DNS_CACHE_SIZE = 8;
static const int DNS_PENDING_MAX = 32;
static const int DNS_MAX_QUESTION = 260;
static const int DNS_RX_QUEUE_SIZE = 128;
static const int UPSTREAM_RX_QUEUE_SIZE = 32;
static const size_t DNS_RX_QUEUE_MAX_BYTES = 64 * 1024;
static const size_t UPSTREAM_RX_QUEUE_MAX_BYTES = 16 * 1024;
static const uint32_t DNS_CACHE_MAX_AGE_MS = 300000UL;
static const uint32_t DNS_UPSTREAM_TIMEOUT_MS = 1000UL;

// ---- globals ----
AsyncUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// Keep only a short, volatile window on the device. The dashboard polls this
// ring buffer and can retain received entries in the browser's localStorage.
static const uint8_t BLOCK_LOG_SIZE = 12;
struct BlockLogEvent {
  uint32_t id = 0;
  uint32_t atMs = 0;
  uint32_t ip = 0;
  uint8_t reason = 0;  // 1 = blocklist, 2 = custom domain, 3 = banned client
  char domain[254] = {0};
};
static BlockLogEvent blockLog[BLOCK_LOG_SIZE];
static uint32_t blockLogSeq = 0;
static uint32_t blockLogBootId = 0;

// 14-bit prefix directory (64 KiB) + small direct-mapped cache.
// Offsets are built by one sequential scan of the sorted blocklist at boot/update.
static uint32_t blPrefixOffsets[PREFIX_BUCKETS + 1];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];
static char dnsApSsid[33] = {0};
static IPAddress dnsApIp;
static String dnsApPassword;
static bool dnsApEnabled = true;
static bool dnsApRunning = false;

struct DnsCacheEntry {
  uint8_t packet[1536];
  uint16_t packetLen = 0;
  uint16_t requestLen = 0;
  uint16_t questionLen = 0;
  uint64_t queryKey = 0;
  uint32_t storedAt = 0;
  uint32_t expiresAt = 0;
  bool valid = false;
};
static DnsCacheEntry dnsCache[DNS_CACHE_SIZE];
static uint8_t dnsCacheNext = 0;
static void invalidateDnsCache() {
  for (int i = 0; i < DNS_CACHE_SIZE; i++) dnsCache[i].valid = false;
  dnsCacheNext = 0;
}

struct DnsPending {
  IPAddress clientIP;
  uint16_t clientPort = 0;
  uint16_t clientId = 0;
  uint16_t upstreamId = 0;
  uint16_t requestLen = 0;
  uint16_t questionLen = 0;
  uint16_t requestFlags = 0;
  uint64_t queryKey = 0;
  uint32_t startedAt = 0;
  uint8_t question[DNS_MAX_QUESTION];
  bool active = false;
};
static DnsPending dnsPending[DNS_PENDING_MAX];

struct DnsDatagram {
  IPAddress ip;
  uint16_t port = 0;
  uint16_t len = 0;
  uint8_t* data = nullptr;
};
static DnsDatagram dnsRxQueue[DNS_RX_QUEUE_SIZE];
static DnsDatagram upstreamRxQueue[UPSTREAM_RX_QUEUE_SIZE];
static uint8_t dnsRxHead = 0, dnsRxTail = 0, dnsRxCount = 0;
static uint8_t upstreamRxHead = 0, upstreamRxTail = 0, upstreamRxCount = 0;
static uint32_t dnsRxDrops = 0, upstreamRxDrops = 0;
static portMUX_TYPE dnsRxMux = portMUX_INITIALIZER_UNLOCKED;
static size_t dnsRxQueuedBytes = 0, upstreamRxQueuedBytes = 0;
static SemaphoreHandle_t dnsStateMutex = nullptr;

class DnsStateLock {
 public:
  DnsStateLock() : locked(dnsStateMutex && xSemaphoreTake(dnsStateMutex, portMAX_DELAY) == pdTRUE) {}
  ~DnsStateLock() { if (locked) xSemaphoreGive(dnsStateMutex); }
  explicit operator bool() const { return locked; }
  void unlock() { if (locked) { xSemaphoreGive(dnsStateMutex); locked = false; } }
 private:
  bool locked;
};

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 128;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 128;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

enum class StatusLedState : uint8_t {
  None, AccessPoint, Active, Offline, Failure, DownloadingHosts, NoInternet
};
static volatile bool statusLedSetupPortal = false;
static volatile bool statusLedCriticalFailure = false;
static volatile bool statusLedFetchingHosts = false;
static volatile bool statusLedFetchNoInternet = false;
static volatile StatusLedState statusLedTransient = StatusLedState::None;
static volatile uint32_t statusLedTransientUntil = 0;

static StatusLedState currentStatusLedState() {
  if (statusLedCriticalFailure) return StatusLedState::Failure;
  if (statusLedSetupPortal) return StatusLedState::AccessPoint;
  if (statusLedFetchingHosts)
    return statusLedFetchNoInternet ? StatusLedState::NoInternet : StatusLedState::DownloadingHosts;
  StatusLedState transient = statusLedTransient;
  if (transient != StatusLedState::None &&
      (int32_t)(statusLedTransientUntil - millis()) > 0) return transient;
  return WiFi.status() == WL_CONNECTED ? StatusLedState::Active : StatusLedState::Offline;
}

#if defined(RGB_BUILTIN)
static void statusLedTask(void*) {
  StatusLedState previousState = StatusLedState::None;
  bool previousOn = false;
  uint32_t stateStartedAt = millis();
  while (true) {
    const StatusLedState state = currentStatusLedState();
    const uint32_t now = millis();
    const bool stateChanged = state != previousState;
    if (stateChanged) {
      previousState = state;
      stateStartedAt = now;
      previousOn = false;
    }

    uint8_t red = 0, green = 0, blue = 0;
    uint32_t periodMs = 0, onMs = 0;
    bool on = true;
    switch (state) {
      case StatusLedState::AccessPoint:     red = 28; green = 18; periodMs = 1200; onMs = 350; break;
      case StatusLedState::Active:           green = 26; break;
      case StatusLedState::Offline:          green = 20; blue = 18; periodMs = 3000; onMs = 280; break;
      case StatusLedState::Failure:          red = 32; periodMs = 250; onMs = 125; break;
      case StatusLedState::DownloadingHosts: blue = 32; periodMs = 650; onMs = 325; break;
      case StatusLedState::NoInternet:       red = 24; blue = 30; break;
      case StatusLedState::None:             break;
    }

    if (periodMs) on = (now - stateStartedAt) % periodMs < onMs;
    else if (state == StatusLedState::NoInternet) {
      const uint32_t phase = (now - stateStartedAt) % 1000;
      on = phase < 100 || (phase >= 200 && phase < 300) || (phase >= 400 && phase < 500);
    }

    if (state != StatusLedState::None && (stateChanged || on != previousOn)) {
      rgbLedWrite(RGB_BUILTIN, on ? red : 0, on ? green : 0, on ? blue : 0);
    }
    previousOn = on;
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}

static void beginStatusLed() {
  xTaskCreate(statusLedTask, "status-led", 2048, nullptr, 1, nullptr);
}
#else
static void beginStatusLed() {}
#endif

static void finishHostFetch(StatusLedState result) {
  statusLedFetchingHosts = false;
  statusLedFetchNoInternet = false;
  if (result == StatusLedState::NoInternet || result == StatusLedState::Failure) {
    statusLedTransientUntil = millis() + 4000UL;
    statusLedTransient = result;
  } else {
    statusLedTransient = StatusLedState::None;
  }
}

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static bool buildFlashIndex() {
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
  if (!blocklist || numHashes == 0) return true;
  if (!blocklist.seek(0)) return false;

  uint32_t nextBoundary = 0;
  uint32_t pos = 0;
  while (pos < numHashes) {
    uint32_t count = numHashes - pos;
    if (count > MAX_RANGE) count = MAX_RANGE;
    size_t bytes = (size_t)count * HASH_BYTES;
    if (blocklist.read(rangeBuf, bytes) != bytes) return false;

    for (uint32_t i = 0; i < count; i++) {
      uint32_t prefix = (uint32_t)(unpackHash(rangeBuf + i * HASH_BYTES) >> PREFIX_SHIFT);
      if (prefix >= PREFIX_BUCKETS) return false;
      while (nextBoundary <= prefix) blPrefixOffsets[nextBoundary++] = pos + i;
    }
    pos += count;
  }
  while (nextBoundary <= PREFIX_BUCKETS) blPrefixOffsets[nextBoundary++] = numHashes;
  return true;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint32_t prefix = (uint32_t)(h >> PREFIX_SHIFT);
  uint32_t startPos = blPrefixOffsets[prefix];
  uint32_t endPos = blPrefixOffsets[prefix + 1];
  if (startPos >= endPos) return false;

  uint32_t rangeCount = endPos - startPos;
  if (rangeCount <= (uint32_t)MAX_RANGE) {
    size_t bytes = (size_t)rangeCount * HASH_BYTES;
    if (!blocklist.seek(startPos * HASH_BYTES) || blocklist.read(rangeBuf, bytes) != bytes) return false;
    for (uint32_t i = 0; i < rangeCount; i++) {
      uint64_t value = unpackHash(rangeBuf + i * HASH_BYTES);
      if (value == h) return true;
      if (value > h) break;
    }
    return false;
  }

  // User-supplied lists can be skewed. Preserve correctness without overrunning the
  // bounded buffer by binary-searching any unusually dense prefix bucket in flash.
  uint32_t lo = startPos, hi = endPos;
  uint8_t item[HASH_BYTES];
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    if (!blocklist.seek(mid * HASH_BYTES) || blocklist.read(item, HASH_BYTES) != HASH_BYTES) return false;
    if (unpackHash(item) < h) lo = mid + 1;
    else hi = mid;
  }
  if (lo >= endPos || !blocklist.seek(lo * HASH_BYTES) || blocklist.read(item, HASH_BYTES) != HASH_BYTES) return false;
  return unpackHash(item) == h;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h, const char** reasonOut = nullptr) {
  if (inCustom(h)) {
    if (reasonOut) *reasonOut = "custom";
    return true;
  }
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) {
      bool res = cacheRes[slot] != 0;
      if (res && reasonOut) *reasonOut = "list";
      return res;
    }
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  if (res && reasonOut) *reasonOut = "list";
  return res;
}

static bool isBlocked(const char* domain, const char** reasonOut = nullptr) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h, reasonOut)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

static void logBlockedQuery(const char* domain, uint32_t ip, const char* reason) {
  uint32_t id = ++blockLogSeq;
  if (id == 0) id = ++blockLogSeq;
  BlockLogEvent& event = blockLog[(id - 1) % BLOCK_LOG_SIZE];
  event.id = id;
  event.atMs = millis();
  event.ip = ip;
  event.reason = reason && strcmp(reason, "custom") == 0 ? 2 :
                 reason && strcmp(reason, "client") == 0 ? 3 : 1;
  size_t len = domain ? strlen(domain) : 0;
  if (len >= sizeof(event.domain)) len = sizeof(event.domain) - 1;
  if (len) memcpy(event.domain, domain, len);
  event.domain[len] = '\0';
}

// ---------- persistence ----------
static void loadCustom() {
  if (!LittleFS.exists("/custom.txt") && LittleFS.exists("/custom.old") &&
      !LittleFS.rename("/custom.old", "/custom.txt")) return;
  LittleFS.remove("/custom.new");
  if (LittleFS.exists("/custom.txt")) LittleFS.remove("/custom.old");
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static bool saveCustom() {
  File f = LittleFS.open("/custom.new", "w"); if (!f) return false;
  bool ok = true;
  for (int i = 0; i < numCustom; i++) {
    String line = customDom[i]; line += '\n';
    if (f.print(line) != line.length()) { ok = false; break; }
  }
  f.close();
  if (!ok) { LittleFS.remove("/custom.new"); return false; }
  const bool hadActive = LittleFS.exists("/custom.txt");
  LittleFS.remove("/custom.old");
  if (hadActive && !LittleFS.rename("/custom.txt", "/custom.old")) {
    LittleFS.remove("/custom.new");
    return false;
  }
  if (!LittleFS.rename("/custom.new", "/custom.txt")) {
    if (hadActive) LittleFS.rename("/custom.old", "/custom.txt");
    LittleFS.remove("/custom.new");
    return false;
  }
  LittleFS.remove("/custom.old");
  return true;
}
static bool validCustomDomain(const String& domain) {
  if (!domain.length() || domain.length() > 253 || domain[0] == '.' || domain[domain.length() - 1] == '.') return false;
  size_t labelLength = 0;
  for (size_t i = 0; i < domain.length(); i++) {
    const char ch = domain[i];
    if (ch == '.') {
      if (!labelLength || labelLength > 63) return false;
      labelLength = 0;
    } else {
      if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_')) return false;
      if (++labelLength > 63) return false;
    }
  }
  return labelLength > 0;
}
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!validCustomDomain(d) || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++;
  if (!saveCustom()) { numCustom--; return false; }
  invalidateDnsCache();
  return true;
}
static bool removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    String removedDomain = customDom[i];
    uint64_t removedHash = customHash[i];
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--;
    if (!saveCustom()) {
      for (int j = numCustom; j > i; j--) { customDom[j] = customDom[j-1]; customHash[j] = customHash[j-1]; }
      customDom[i] = removedDomain; customHash[i] = removedHash; numCustom++;
      return false;
    }
    invalidateDnsCache(); return true;
  }
  return false;
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static const char* BANNED_TEMP_PATH = "/banned.new";
static const char* BANNED_BACKUP_PATH = "/banned.old";
static void recoverBannedSwap() {
  if (!LittleFS.exists("/banned.txt") && LittleFS.exists(BANNED_BACKUP_PATH) &&
      !LittleFS.rename(BANNED_BACKUP_PATH, "/banned.txt")) return;
  LittleFS.remove(BANNED_TEMP_PATH);
  if (LittleFS.exists("/banned.txt")) LittleFS.remove(BANNED_BACKUP_PATH);
}
static bool saveBanned() {
  File f = LittleFS.open(BANNED_TEMP_PATH, "w"); if (!f) return false;
  bool ok = true;
  for (int i = 0; i < numBanned; i++) {
    IPAddress ip(bannedIP[i]);
    String line = ip.toString(); line += '\n';
    if (f.print(line) != line.length()) { ok = false; break; }
  }
  f.close();
  if (!ok) { LittleFS.remove(BANNED_TEMP_PATH); return false; }
  const bool hadActive = LittleFS.exists("/banned.txt");
  LittleFS.remove(BANNED_BACKUP_PATH);
  if (hadActive && !LittleFS.rename("/banned.txt", BANNED_BACKUP_PATH)) {
    LittleFS.remove(BANNED_TEMP_PATH);
    return false;
  }
  if (!LittleFS.rename(BANNED_TEMP_PATH, "/banned.txt")) {
    if (hadActive) LittleFS.rename(BANNED_BACKUP_PATH, "/banned.txt");
    LittleFS.remove(BANNED_TEMP_PATH);
    return false;
  }
  LittleFS.remove(BANNED_BACKUP_PATH);
  return true;
}
static bool setBannedIP(uint32_t ip, bool banned) {
  int found = -1;
  for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) { found = i; break; }
  bool added = false;
  bool removed = false;
  if (banned && found < 0) {
    if (numBanned >= MAX_BAN) return false;
    bannedIP[numBanned++] = ip;
    added = true;
  } else if (!banned && found >= 0) {
    for (int i = found; i + 1 < numBanned; i++) bannedIP[i] = bannedIP[i + 1];
    numBanned--;
    removed = true;
  }
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) clients[i].banned = banned;
  if (saveBanned()) return true;
  if (added) numBanned--;
  if (removed && numBanned < MAX_BAN) bannedIP[numBanned++] = ip;
  const bool current = isBannedIP(ip);
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) clients[i].banned = current;
  return false;
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 17 || (pkt[2] & 0x80) || pkt[4] != 0 || pkt[5] != 1) return 0;
  int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    size_t nextLength = o + (o ? 1U : 0U) + l;
    if (l > 63 || nextLength > 253 || i + l > len) return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) {
      uint8_t ch = pkt[i++];
      if (ch < 0x21 || ch > 0x7e || ch == '.') return 0;
      out[o++] = tolower(ch);
    }
  }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x80 | (buf[2] & 0x79); buf[3] = 0x80 | (buf[3] & 0x10);
  buf[4] = 0; buf[5] = 1; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0;
  buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}

static uint64_t dnsQueryKey(const uint8_t* pkt, size_t len) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 2; i < len; i++) { h ^= pkt[i]; h *= 0x100000001b3ULL; }
  return h;
}

static bool dnsSkipName(const uint8_t* pkt, size_t len, size_t& pos) {
  size_t cursor = pos, resume = 0; bool jumped = false; int steps = 0;
  while (cursor < len && steps++ < 128) {
    uint8_t n = pkt[cursor++];
    if (n == 0) { pos = jumped ? resume : cursor; return true; }
    if ((n & 0xC0) == 0xC0) {
      if (cursor >= len) return false;
      size_t target = ((size_t)(n & 0x3F) << 8) | pkt[cursor++];
      if (target >= len) return false;
      if (!jumped) { resume = cursor; jumped = true; }
      cursor = target;
      continue;
    }
    if (n & 0xC0 || cursor + n > len) return false;
    cursor += n;
  }
  return false;
}

static bool dnsResponseTtl(const uint8_t* pkt, size_t len, uint16_t questionLen, uint32_t* ttlOut) {
  if (len < 12 || !(pkt[2] & 0x80) || (pkt[2] & 0x02) || (pkt[3] & 0x0F) != 0) return false;
  if (pkt[4] != 0 || pkt[5] != 1) return false;
  uint16_t answers = ((uint16_t)pkt[6] << 8) | pkt[7];
  uint16_t authority = ((uint16_t)pkt[8] << 8) | pkt[9];
  uint16_t additional = ((uint16_t)pkt[10] << 8) | pkt[11];
  if (answers == 0 || 12U + questionLen > len) return false;

  size_t pos = 12U + questionLen;
  uint32_t minTtl = UINT32_MAX;
  uint32_t records = (uint32_t)answers + authority + additional;
  for (uint32_t i = 0; i < records; i++) {
    if (!dnsSkipName(pkt, len, pos) || pos + 10 > len) return false;
    uint16_t type = ((uint16_t)pkt[pos] << 8) | pkt[pos + 1];
    uint32_t ttl = ((uint32_t)pkt[pos + 4] << 24) | ((uint32_t)pkt[pos + 5] << 16) |
                   ((uint32_t)pkt[pos + 6] << 8) | pkt[pos + 7];
    uint16_t rdlen = ((uint16_t)pkt[pos + 8] << 8) | pkt[pos + 9];
    pos += 10;
    if (pos + rdlen > len) return false;
    if (type != 41 && ttl < minTtl) minTtl = ttl;  // OPT's TTL field contains flags, not a cache TTL.
    pos += rdlen;
  }
  if (minTtl == UINT32_MAX || minTtl == 0) return false;
  *ttlOut = minTtl;
  return true;
}

static bool dnsCacheLookup(const uint8_t* query, uint16_t requestLen, uint16_t questionLen,
                           uint64_t queryKey, int* replyLen) {
  uint32_t now = millis();
  for (int i = 0; i < DNS_CACHE_SIZE; i++) {
    DnsCacheEntry& e = dnsCache[i];
    if (!e.valid) continue;
    if ((int32_t)(now - e.expiresAt) >= 0) { e.valid = false; continue; }
    if (e.queryKey != queryKey || e.requestLen != requestLen || e.questionLen != questionLen ||
        e.packetLen < 12 + questionLen || memcmp(e.packet + 12, query + 12, questionLen) != 0) continue;
    uint8_t id0 = query[0], id1 = query[1];
    memcpy(buf, e.packet, e.packetLen);
    buf[0] = id0; buf[1] = id1;
    size_t pos = 12U + questionLen;
    const uint32_t elapsedSeconds = (now - e.storedAt) / 1000UL;
    const uint32_t records = ((uint32_t)buf[6] << 8 | buf[7]) +
                             ((uint32_t)buf[8] << 8 | buf[9]) +
                             ((uint32_t)buf[10] << 8 | buf[11]);
    bool validRecords = pos <= e.packetLen;
    for (uint32_t record = 0; validRecords && record < records; record++) {
      if (!dnsSkipName(buf, e.packetLen, pos) || pos + 10 > e.packetLen) { validRecords = false; break; }
      uint16_t type = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
      uint32_t ttl = ((uint32_t)buf[pos + 4] << 24) | ((uint32_t)buf[pos + 5] << 16) |
                     ((uint32_t)buf[pos + 6] << 8) | buf[pos + 7];
      if (type != 41) {
        ttl = ttl > elapsedSeconds ? ttl - elapsedSeconds : 0;
        buf[pos + 4] = ttl >> 24; buf[pos + 5] = ttl >> 16;
        buf[pos + 6] = ttl >> 8; buf[pos + 7] = ttl;
      }
      uint16_t rdlen = ((uint16_t)buf[pos + 8] << 8) | buf[pos + 9];
      pos += 10;
      if (pos + rdlen > e.packetLen) { validRecords = false; break; }
      pos += rdlen;
    }
    if (!validRecords) { e.valid = false; continue; }
    *replyLen = e.packetLen;
    return true;
  }
  return false;
}

static void dnsCacheStore(const uint8_t* response, uint16_t responseLen, uint16_t requestLen,
                          uint16_t questionLen, uint64_t queryKey) {
  uint32_t ttl;
  if (responseLen > sizeof(buf) || responseLen < 12 + questionLen ||
      !dnsResponseTtl(response, responseLen, questionLen, &ttl)) return;
  DnsCacheEntry& e = dnsCache[dnsCacheNext++ % DNS_CACHE_SIZE];
  memcpy(e.packet, response, responseLen);
  e.packetLen = responseLen;
  e.requestLen = requestLen;
  e.questionLen = questionLen;
  e.queryKey = queryKey;
  e.storedAt = millis();
  if (ttl > DNS_CACHE_MAX_AGE_MS / 1000) ttl = DNS_CACHE_MAX_AGE_MS / 1000;
  e.expiresAt = e.storedAt + ttl * 1000UL;
  e.valid = true;
}

template<size_t N>
static void enqueueDatagram(DnsDatagram (&queue)[N], uint8_t& head,
                            uint8_t& count, size_t& queuedBytes, size_t maxBytes, uint32_t& drops,
                            AsyncUDPPacket& packet) {
  size_t len = packet.length();
  if (len == 0 || len > sizeof(buf) || len > maxBytes) {
    portENTER_CRITICAL(&dnsRxMux); drops++; portEXIT_CRITICAL(&dnsRxMux);
    return;
  }
  IPAddress ip = packet.remoteIP();
  uint16_t port = packet.remotePort();
  uint8_t* data = (uint8_t*)malloc(len);
  if (!data) {
    portENTER_CRITICAL(&dnsRxMux); drops++; portEXIT_CRITICAL(&dnsRxMux);
    return;
  }
  memcpy(data, packet.data(), len);
  portENTER_CRITICAL(&dnsRxMux);
  if (count >= N || queuedBytes + len > maxBytes) {
    drops++;
    portEXIT_CRITICAL(&dnsRxMux);
    free(data);
    return;
  }
  DnsDatagram& d = queue[head];
  d.ip = ip; d.port = port; d.len = len;
  d.data = data;
  head = (head + 1) % N;
  count++;
  queuedBytes += len;
  portEXIT_CRITICAL(&dnsRxMux);
}

static bool requeueClientDatagram(const IPAddress& ip, uint16_t port, uint16_t len, const uint8_t* data) {
  uint8_t* copy = (uint8_t*)malloc(len);
  if (!copy) {
    portENTER_CRITICAL(&dnsRxMux); dnsRxDrops++; portEXIT_CRITICAL(&dnsRxMux);
    return false;
  }
  memcpy(copy, data, len);
  portENTER_CRITICAL(&dnsRxMux);
  if (dnsRxCount >= DNS_RX_QUEUE_SIZE || dnsRxQueuedBytes + len > DNS_RX_QUEUE_MAX_BYTES) {
    dnsRxDrops++;
    portEXIT_CRITICAL(&dnsRxMux);
    free(copy);
    return false;
  }
  DnsDatagram& d = dnsRxQueue[dnsRxHead];
  d.ip = ip; d.port = port; d.len = len; d.data = copy;
  dnsRxHead = (dnsRxHead + 1) % DNS_RX_QUEUE_SIZE;
  dnsRxCount++;
  dnsRxQueuedBytes += len;
  portEXIT_CRITICAL(&dnsRxMux);
  return true;
}

template<size_t N>
static bool dequeueDatagram(DnsDatagram (&queue)[N], uint8_t& tail,
                            uint8_t& count, size_t& queuedBytes, IPAddress* ip, uint16_t* port,
                            uint16_t* len, uint8_t* data) {
  bool found = false;
  uint8_t* packetData = nullptr;
  portENTER_CRITICAL(&dnsRxMux);
  if (count) {
    DnsDatagram& d = queue[tail];
    *ip = d.ip; *port = d.port; *len = d.len;
    packetData = d.data;
    d.data = nullptr;
    tail = (tail + 1) % N;
    count--;
    queuedBytes -= *len;
    found = true;
  }
  portEXIT_CRITICAL(&dnsRxMux);
  if (found) { memcpy(data, packetData, *len); free(packetData); }
  return found;
}

static void onClientDnsPacket(AsyncUDPPacket& packet) {
  enqueueDatagram(dnsRxQueue, dnsRxHead, dnsRxCount, dnsRxQueuedBytes,
                  DNS_RX_QUEUE_MAX_BYTES, dnsRxDrops, packet);
}

static void onUpstreamPacket(AsyncUDPPacket& packet) {
  enqueueDatagram(upstreamRxQueue, upstreamRxHead, upstreamRxCount, upstreamRxQueuedBytes,
                  UPSTREAM_RX_QUEUE_MAX_BYTES, upstreamRxDrops, packet);
}

static void sendDnsReply(const IPAddress& ip, uint16_t port, int len) {
  if (len <= 0) return;
  dnsServer.writeTo(buf, len, ip, port);
}

static int buildServFail(int qend) {
  buf[2] = 0x80 | (buf[2] & 0x79);  // QR, opcode, and the request's RD bit.
  buf[3] = 0x82 | (buf[3] & 0x10);   // RA + SERVFAIL; preserve CD.
  buf[4] = 0; buf[5] = (qend >= 12) ? 1 : 0;
  buf[6] = buf[7] = buf[8] = buf[9] = buf[10] = buf[11] = 0;
  return qend >= 12 ? qend : 12;
}

static bool upstreamIdInUse(uint16_t id) {
  for (int i = 0; i < DNS_PENDING_MAX; i++)
    if (dnsPending[i].active && dnsPending[i].upstreamId == id) return true;
  return false;
}

static bool hasPendingSlot() {
  for (int i = 0; i < DNS_PENDING_MAX; i++) if (!dnsPending[i].active) return true;
  return false;
}

static bool queueUpstream(int qlen, int qend, const IPAddress& clientIP, uint16_t clientPort,
                          uint64_t queryKey) {
  int questionLen = qend - 12;
  if (qend < 17 || qend > qlen || qlen > (int)sizeof(buf) ||
      questionLen > DNS_MAX_QUESTION || questionLen <= 0) return false;
  int slot = -1;
  for (int i = 0; i < DNS_PENDING_MAX; i++) if (!dnsPending[i].active) { slot = i; break; }
  if (slot < 0) return false;

  uint16_t upstreamId = 0;
  for (int attempt = 0; attempt < 32; attempt++) {
    upstreamId = (uint16_t)esp_random();
    if (!upstreamIdInUse(upstreamId)) break;
  }
  if (upstreamIdInUse(upstreamId)) return false;

  DnsPending& p = dnsPending[slot];
  p.clientIP = clientIP;
  p.clientPort = clientPort;
  p.clientId = ((uint16_t)buf[0] << 8) | buf[1];
  p.upstreamId = upstreamId;
  p.requestLen = qlen;
  p.questionLen = questionLen;
  p.requestFlags = ((uint16_t)buf[2] << 8) | buf[3];
  p.queryKey = queryKey;
  memcpy(p.question, buf + 12, questionLen);

  uint8_t clientIdHi = buf[0], clientIdLo = buf[1];
  buf[0] = upstreamId >> 8; buf[1] = upstreamId & 0xFF;
  size_t sent = upstreamCli.writeTo(buf, qlen, UPSTREAM, UPSTREAM_PORT);
  if (sent != (size_t)qlen) {
    buf[0] = clientIdHi; buf[1] = clientIdLo;
    return false;
  }
  p.startedAt = millis();
  p.active = true;
  return true;
}

static int buildPendingServFail(const DnsPending& p) {
  memset(buf, 0, 12);
  buf[0] = p.clientId >> 8; buf[1] = p.clientId & 0xFF;
  buf[2] = 0x80 | ((p.requestFlags >> 8) & 0x79);
  buf[3] = 0x82 | (p.requestFlags & 0x10);
  buf[5] = 1;
  memcpy(buf + 12, p.question, p.questionLen);
  return 12 + p.questionLen;
}

static bool pollUpstream() {
  bool did = false;
  for (int budget = 0; budget < 32; budget++) {
    IPAddress sourceIP; uint16_t sourcePort = 0; uint16_t n = 0;
    if (!dequeueDatagram(upstreamRxQueue, upstreamRxTail, upstreamRxCount, upstreamRxQueuedBytes,
                         &sourceIP, &sourcePort, &n, buf)) break;
    if (sourceIP != UPSTREAM || sourcePort != UPSTREAM_PORT || n < 12 ||
        (buf[2] & 0x80) == 0) continue;

    for (int i = 0; i < DNS_PENDING_MAX; i++) {
      DnsPending& p = dnsPending[i];
      if (!p.active || buf[0] != (p.upstreamId >> 8) || buf[1] != (p.upstreamId & 0xFF) ||
          n < 12 + p.questionLen || memcmp(buf + 12, p.question, p.questionLen) != 0) continue;
      buf[0] = p.clientId >> 8; buf[1] = p.clientId & 0xFF;
      dnsCacheStore(buf, n, p.requestLen, p.questionLen, p.queryKey);
      sendDnsReply(p.clientIP, p.clientPort, n);
      p.active = false;
      did = true;
      break;
    }
  }

  uint32_t now = millis();
  for (int i = 0; i < DNS_PENDING_MAX; i++) {
    DnsPending& p = dnsPending[i];
    if (!p.active || now - p.startedAt < DNS_UPSTREAM_TIMEOUT_MS) continue;
    int len = buildPendingServFail(p);
    sendDnsReply(p.clientIP, p.clientPort, len);
    p.active = false;
    did = true;
  }
  return did;
}

// Process a bounded burst without waiting for upstream replies. This runs in the
// DNS worker, separate from synchronous dashboard, upload, and update handlers.
static bool handleDns() {
  bool did = false;
  uint8_t queuedAtStart;
  portENTER_CRITICAL(&dnsRxMux); queuedAtStart = dnsRxCount; portEXIT_CRITICAL(&dnsRxMux);
  int scanBudget = queuedAtStart < 16 ? queuedAtStart : 16;
  for (int budget = 0; budget < scanBudget; budget++) {
    IPAddress cip; uint16_t cport = 0; uint16_t qlen = 0;
    if (!dequeueDatagram(dnsRxQueue, dnsRxTail, dnsRxCount, dnsRxQueuedBytes,
                         &cip, &cport, &qlen, buf)) break;
    did = true;
    if (qlen < 12) continue;

    char domain[256]; uint16_t qtype = 0; int qend = 0;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    if (qend < 17 || qend > qlen) { sendDnsReply(cip, cport, buildServFail(0)); continue; }

    Dev* c = getClient((uint32_t)cip);
    bool ban = isBannedIP((uint32_t)cip);
    const char* blockReason = ban ? "client" : nullptr;
    bool blocked = ban || (blockingOn && dl && isBlocked(domain, &blockReason));
    if (blocked) {
      int rlen = buildBlocked(qend, qtype);
      totalBlocked++; if (c) c->blocked++;
      logBlockedQuery(domain, (uint32_t)cip, blockReason);
      sendDnsReply(cip, cport, rlen);
      continue;
    }

    uint16_t questionLen = qend - 12;
    uint64_t queryKey = dnsQueryKey(buf, qlen);
    int rlen = 0;
    if (dnsCacheLookup(buf, qlen, questionLen, queryKey, &rlen)) {
      totalAllowed++; if (c) c->allowed++;
      sendDnsReply(cip, cport, rlen);
    } else {
      bool queued = queueUpstream(qlen, qend, cip, cport, queryKey);
      if (!queued && !hasPendingSlot()) {
        if (requeueClientDatagram(cip, cport, qlen, buf)) continue;
        continue;
      }
      totalAllowed++; if (c) c->allowed++;
      if (!queued) sendDnsReply(cip, cport, buildServFail(qend));
    }
  }
  return did;
}

static void dnsProcessingTask(void*) {
  while (true) {
    bool busy = false;
    {
      DnsStateLock state;
      if (state) {
        busy = pollUpstream();
        busy = handleDns() || busy;
        if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) {
          blockingOn = true;
          resumeAt = 0;
        }
      }
    }
    if (!busy) vTaskDelay(pdMS_TO_TICKS(1));
    else taskYIELD();
  }
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) {
  String o; o.reserve(s.length() + 8);
  for (size_t i = 0; i < s.length(); i++) {
    uint8_t ch = (uint8_t)s[i];
    switch (ch) {
      case '"': o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\b': o += "\\b"; break;
      case '\f': o += "\\f"; break;
      case '\n': o += "\\n"; break;
      case '\r': o += "\\r"; break;
      case '\t': o += "\\t"; break;
      default:
        if (ch < 0x20 || ch >= 0x7f) {
          char escaped[7]; snprintf(escaped, sizeof(escaped), "\\u%04x", ch); o += escaped;
        } else o += (char)ch;
    }
  }
  return o;
}
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c6-adblock";
static const uint32_t WEB_SESSION_TTL_MS = 12UL * 60UL * 60UL * 1000UL;
static const uint8_t WEB_SESSION_COUNT = 4;
static String dashboardUser = WEB_USER;
static String dashboardPass = WEB_PASS;
struct WebSession {
  char token[33] = {0};
  uint32_t expiresAt = 0;
  uint32_t lastUsedAt = 0;
  bool active = false;
};
static WebSession webSessions[WEB_SESSION_COUNT];

static int sessionForRequest() {
  String cookies = web.header("Cookie");
  int offset = 0;
  while (offset < (int)cookies.length()) {
    while (offset < (int)cookies.length() && (cookies[offset] == ';' || cookies[offset] == ' ')) offset++;
    int equals = cookies.indexOf('=', offset);
    if (equals < 0) break;
    int end = cookies.indexOf(';', equals + 1);
    if (end < 0) end = cookies.length();
    String name = cookies.substring(offset, equals); name.trim();
    if (name == "c6session") {
      String value = cookies.substring(equals + 1, end); value.trim();
      if (value.length() != 32) return -1;
      uint32_t now = millis();
      for (uint8_t i = 0; i < WEB_SESSION_COUNT; i++) {
        WebSession& session = webSessions[i];
        if (!session.active) continue;
        if ((int32_t)(now - session.expiresAt) >= 0) { session.active = false; continue; }
        if (memcmp(value.c_str(), session.token, 32) == 0) {
          session.lastUsedAt = now;
          return i;
        }
      }
      return -1;
    }
    offset = end + 1;
  }
  return -1;
}

static int allocateWebSession() {
  uint32_t now = millis();
  int slot = -1;
  uint32_t oldestAge = 0;
  for (uint8_t i = 0; i < WEB_SESSION_COUNT; i++) {
    WebSession& session = webSessions[i];
    if (session.active && (int32_t)(now - session.expiresAt) >= 0) session.active = false;
    if (!session.active) return i;
    uint32_t age = now - session.lastUsedAt;
    if (slot < 0 || age > oldestAge) { slot = i; oldestAge = age; }
  }
  return slot;
}

static bool requireSession() {
  if (sessionForRequest() >= 0) return true;
  web.sendHeader("Cache-Control", "no-store");
  web.send(401, "text/plain", "login required");
  return false;
}

static bool requestHasControlSession() {
  return web.header(CSRF_HEADER) == CSRF_VALUE && sessionForRequest() >= 0;
}

static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) {
    web.send(403, "text/plain", "missing CSRF header");
    return false;
  }
  return requireSession();
}

static void handleLogin() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) {
    web.send(403, "text/plain", "missing CSRF header");
    return;
  }
  String username = web.arg("username"), password = web.arg("password");
  if (!username.equals(dashboardUser) || !password.equals(dashboardPass)) {
    web.sendHeader("Cache-Control", "no-store");
    web.send(401, "text/plain", "incorrect username or password");
    return;
  }

  int slot = allocateWebSession();
  if (slot < 0) { web.send(503, "text/plain", "no dashboard session available"); return; }
  WebSession& session = webSessions[slot];
  snprintf(session.token, sizeof(session.token), "%08lx%08lx%08lx%08lx",
           (unsigned long)esp_random(), (unsigned long)esp_random(),
           (unsigned long)esp_random(), (unsigned long)esp_random());
  session.active = true;
  session.lastUsedAt = millis();
  session.expiresAt = session.lastUsedAt + WEB_SESSION_TTL_MS;
  web.sendHeader("Cache-Control", "no-store");
  String cookie = "c6session="; cookie += session.token;
  cookie += "; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200";
  web.sendHeader("Set-Cookie", cookie);
  web.send(200, "text/plain", "ok");
}

static void handleLogout() {
  if (!requireAuth()) return;
  int slot = sessionForRequest();
  if (slot >= 0) webSessions[slot].active = false;
  web.sendHeader("Cache-Control", "no-store");
  web.sendHeader("Set-Cookie", "c6session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
  web.send(200, "text/plain", "ok");
}

static void handleDashboardRoot() {
  web.sendHeader("Cache-Control", "no-store");
  if (sessionForRequest() >= 0) web.send_P(200, "text/html", PAGE);
  else web.send_P(200, "text/html", LOGIN_PAGE);
}

static void handleStats() {
  if (!requireSession()) return;
  DnsStateLock state;
  if (!state) { web.send(503, "text/plain", "DNS state unavailable"); return; }
  uint32_t up = millis() / 1000;
  uint32_t clientDrops, upstreamDrops;
  portENTER_CRITICAL(&dnsRxMux);
  clientDrops = dnsRxDrops; upstreamDrops = upstreamRxDrops;
  portEXIT_CRITICAL(&dnsRxMux);
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"webUser\":\"" + jesc(dashboardUser) + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"wifiConnected\":" + (WiFi.status() == WL_CONNECTED ? "true" : "false") +
             ",\"wifiSsid\":\"" + jesc(WiFi.SSID()) + "\"" +
             ",\"dns_rx_drops\":" + String(clientDrops) + ",\"upstream_rx_drops\":" + String(upstreamDrops) +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"hotspot\":{\"enabled\":" + (dnsApEnabled ? "true" : "false") +
             ",\"running\":" + (dnsApRunning ? "true" : "false") +
             ",\"ssid\":\"" + jesc(String(dnsApSsid)) + "\",\"ip\":\"" +
             (dnsApRunning ? dnsApIp.toString() : String("")) + "\",\"clients\":" +
             String(dnsApRunning ? WiFi.softAPgetStationNum() : 0) + "}" +
             ",\"defcreds\":" + ((dashboardPass == "CHANGE_ME_WEB_PASSWORD" ||
                                      strcmp(dnsApPassword.c_str(), "CHANGE_ME_AP_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  state.unlock();
  web.sendHeader("Cache-Control", "no-store");
  web.send(200, "application/json", j);
}

// Short polling keeps the single-threaded WebServer loop available to DNS.
// An open SSE response would hold that loop while the browser stays connected.
static void handleBlockedEvents() {
  if (!requireSession()) return;
  DnsStateLock state;
  if (!state) { web.send(503, "text/plain", "DNS state unavailable"); return; }
  uint32_t after = web.hasArg("after") ? (uint32_t)strtoul(web.arg("after").c_str(), nullptr, 10) : 0;
  uint32_t clientBoot = web.hasArg("boot") ? (uint32_t)strtoul(web.arg("boot").c_str(), nullptr, 10) : 0;
  uint32_t latest = blockLogSeq;
  if (clientBoot != blockLogBootId || after > latest) after = 0;

  uint32_t oldest = latest >= BLOCK_LOG_SIZE ? latest - BLOCK_LOG_SIZE + 1 : 1;
  uint32_t lost = latest && after + 1 < oldest ? oldest - after - 1 : 0;
  if (lost) after = oldest - 1;

  size_t reserve = 96;
  for (uint32_t id = after + 1; id <= latest; id++) {
    BlockLogEvent& event = blockLog[(id - 1) % BLOCK_LOG_SIZE];
    if (event.id == id) reserve += strlen(event.domain) + 80;
  }
  String json; json.reserve(reserve);
  json = "{\"boot\":"; json += String(blockLogBootId);
  json += ",\"latest\":"; json += String(latest);
  json += ",\"lost\":"; json += String(lost);
  json += ",\"events\":[";
  bool first = true;
  for (uint32_t id = after + 1; id <= latest; id++) {
    BlockLogEvent& event = blockLog[(id - 1) % BLOCK_LOG_SIZE];
    if (event.id != id) continue;
    if (!first) json += ',';
    first = false;
    const char* reason = event.reason == 2 ? "custom" : event.reason == 3 ? "client" : "list";
    json += "{\"id\":"; json += String(event.id);
    json += ",\"at\":"; json += String(event.atMs);
    json += ",\"ip\":\""; json += IPAddress(event.ip).toString(); json += '"';
    json += ",\"domain\":\""; json += jesc(String(event.domain)); json += '"';
    json += ",\"reason\":\""; json += reason; json += "\"}";
  }
  json += "]}";
  state.unlock();
  web.sendHeader("Cache-Control", "no-store");
  web.send(200, "application/json", json);
}
// Every dashboard API uses the login session; state-changing requests also need
// a custom header so cross-origin forms and image requests cannot trigger them.
static bool saveDnsApSettings(const String& ssid, const String& password, bool enabled);
static bool hasControlCharacter(const String& value);
static bool validDashboardPass(const String& value);
static bool clearPreferencesNamespace(const char* name) {
  if (!prefs.begin(name, false)) return false;
  bool ok = prefs.clear();
  prefs.end();
  return ok;
}
static bool removeConfigFile(const char* path) {
  return !LittleFS.exists(path) || LittleFS.remove(path);
}
static bool clearAllConfiguration() {
  const char* namespaces[] = {"wifi", "hotspot", "web_auth"};
  for (const char* name : namespaces) {
    if (!clearPreferencesNamespace(name)) return false;
  }
  const char* files[] = {"/custom.txt", "/custom.new", "/custom.old", "/banned.txt", "/banned.new", "/banned.old",
                         "/update.cfg", "/blocklist.new"};
  for (const char* path : files) {
    if (!removeConfigFile(path)) return false;
  }
  return true;
}
static void handleDashboardCredentials() {
  if (!requireAuth()) return;

  String username = web.arg("username"), password = web.arg("password");
  if (!username.length() || username.length() > 32 || hasControlCharacter(username)) {
    web.send(400, "text/plain", "Username must be 1-32 bytes and contain no control characters");
    return;
  }
  bool passwordChanged = password.length() > 0;
  if (!passwordChanged) password = dashboardPass;
  if ((passwordChanged && password.length() < 8) || !validDashboardPass(password)) {
    web.send(400, "text/plain", "Password must be 8-63 bytes and contain no control characters");
    return;
  }
  if (!prefs.begin("web_auth", false)) {
    web.send(500, "text/plain", "could not save dashboard credentials");
    return;
  }
  String credentials = username; credentials += '\n'; credentials += password;
  bool saved = prefs.putString("credentials", credentials) > 0;
  String check = prefs.getString("credentials", "");
  prefs.end();
  if (!saved || check != credentials) {
    web.send(500, "text/plain", "could not save dashboard credentials");
    return;
  }

  dashboardUser = username;
  dashboardPass = password;
  for (uint8_t i = 0; i < WEB_SESSION_COUNT; i++) {
    webSessions[i].active = false;
    webSessions[i].token[0] = '\0';
  }
  web.sendHeader("Cache-Control", "no-store");
  web.sendHeader("Set-Cookie", "c6session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
  web.send(200, "text/plain", "Dashboard credentials saved; sign in again");
}

static void handleResetConfig() {
  if (!requireAuth()) return;

  if (!clearAllConfiguration()) {
    web.send(500, "text/plain", "could not clear saved device settings");
    return;
  }

  web.sendHeader("Cache-Control", "no-store");
  web.sendHeader("Set-Cookie", "c6session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
  web.send(200, "text/plain", "Saved settings cleared; restarting with defaults");
  delay(350);
  ESP.restart();
}

static void handleHotspotSave() {
  if (!requireAuth()) return;

  String ssid = web.arg("ssid");
  String password = web.arg("password");
  String enabledArg = web.arg("enabled");
  if (!ssid.length() || ssid.length() > 32 || hasControlCharacter(ssid)) {
    web.send(400, "text/plain", "SSID must be 1-32 bytes and contain no control characters");
    return;
  }
  if (enabledArg != "0" && enabledArg != "1") {
    web.send(400, "text/plain", "enabled must be 0 or 1");
    return;
  }
  if (!password.length()) password = dnsApPassword;
  if (password.length() < 8 || password.length() > 63 || hasControlCharacter(password)) {
    web.send(400, "text/plain", "Password must be 8-63 bytes and contain no control characters");
    return;
  }

  bool enabled = enabledArg == "1";
  if (!saveDnsApSettings(ssid, password, enabled)) {
    web.send(500, "text/plain", "could not save hotspot settings");
    return;
  }

  ssid.toCharArray(dnsApSsid, sizeof(dnsApSsid));
  dnsApPassword = password;
  dnsApEnabled = enabled;
  web.send(200, "text/plain", "Hotspot settings saved; device restarting");
  delay(500);
  ESP.restart();
}
static void handleWifiUpdate() {
  if (!requireAuth()) return;

  String ssid = web.arg("ssid");
  String password = web.arg("password");
  if (!ssid.length() || ssid.length() > 32 || hasControlCharacter(ssid)) {
    web.send(400, "text/plain", "SSID must be 1-32 bytes and contain no control characters");
    return;
  }
  if ((password.length() && password.length() < 8) || password.length() > 63 ||
      hasControlCharacter(password)) {
    web.send(400, "text/plain", "WiFi password must be blank for an open network or 8-63 bytes");
    return;
  }
  if (!prefs.begin("wifi", false)) {
    web.send(500, "text/plain", "could not save WiFi credentials");
    return;
  }
  bool saved = prefs.putString("ssid", ssid) > 0;
  prefs.putString("pass", password);
  saved = (prefs.getString("pass", "__missing__") == password) && saved;
  prefs.end();
  if (!saved) {
    web.send(500, "text/plain", "could not save WiFi credentials");
    return;
  }

  web.send(200, "text/plain", "WiFi credentials saved; device restarting");
  delay(700);
  ESP.restart();
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip;
  if (!ip.fromString(web.arg("ip"))) { web.send(400, "text/plain", "invalid client IP"); return; }
  DnsStateLock state;
  if (!state) { web.send(503, "text/plain", "DNS state unavailable"); return; }
  const uint32_t value = (uint32_t)ip;
  const bool wasBanned = isBannedIP(value);
  if (!wasBanned && numBanned >= MAX_BAN) { web.send(507, "text/plain", "ban list is full"); return; }
  if (!setBannedIP(value, !wasBanned)) { web.send(500, "text/plain", "could not save ban list"); return; }
  state.unlock();
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// Keep the active file until the staged replacement is complete and validated.
// This needs enough LittleFS free space for the new file alongside the old one.
static bool reopenBlocklist() {
  if (blocklist) blocklist.close();
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (!blocklist) { numHashes = 0; return false; }
  uint32_t count = blocklist.size() / HASH_BYTES;
  if (count > MAX_INDEXED_HASHES) {
    Serial.printf("[blocklist] %u hashes exceed index capacity %u; forwarding without blocking\n",
                  count, MAX_INDEXED_HASHES);
    blocklist.close(); numHashes = 0;
    return false;
  }
  if (!count) { blocklist.close(); numHashes = 0; return false; }
  numHashes = count;
  if (!buildFlashIndex()) {
    Serial.println("[blocklist] prefix index build failed; forwarding without blocking");
    blocklist.close(); numHashes = 0;
    return false;
  }
  return true;
}
static void beginBlocklistSwap() {
  // Keep the active list open while a replacement is downloaded or uploaded.
  LittleFS.remove(BLOCKLIST_TEMP_PATH);
}
static bool validateBlocklistFile(File& f, size_t& sizeOut) {
  sizeOut = f ? f.size() : 0;
  if (!f || !sizeOut || (sizeOut % HASH_BYTES) != 0 || (sizeOut / HASH_BYTES) > MAX_INDEXED_HASHES || !f.seek(0)) return false;
  uint8_t chunk[1020];  // 204 hashes per read; retain the previous value across chunks.
  size_t remaining = sizeOut;
  uint64_t previous = 0;
  bool havePrevious = false;
  while (remaining) {
    size_t bytes = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
    if (bytes % HASH_BYTES || f.read(chunk, bytes) != bytes) return false;
    for (size_t pos = 0; pos < bytes; pos += HASH_BYTES) {
      const uint64_t value = unpackHash(chunk + pos);
      if (havePrevious && value <= previous) return false;
      previous = value;
      havePrevious = true;
    }
    remaining -= bytes;
  }
  return true;
}
static void recoverBlocklistSwap() {
  // A reboot during the two renames can leave the old list under its backup name.
  if (!LittleFS.exists(BLOCKLIST_PATH) && LittleFS.exists(BLOCKLIST_BACKUP_PATH)) {
    LittleFS.rename(BLOCKLIST_BACKUP_PATH, BLOCKLIST_PATH);
  }
  LittleFS.remove(BLOCKLIST_TEMP_PATH);
}
static void settleBlocklistBackup(bool activeOk) {
  if (!LittleFS.exists(BLOCKLIST_BACKUP_PATH)) return;
  if (activeOk) {
    LittleFS.remove(BLOCKLIST_BACKUP_PATH);
    return;
  }
  if (blocklist) blocklist.close();
  LittleFS.remove(BLOCKLIST_PATH);
  if (LittleFS.rename(BLOCKLIST_BACKUP_PATH, BLOCKLIST_PATH)) reopenBlocklist();
}
static bool commitNewBlocklist() {
  File staged = LittleFS.open(BLOCKLIST_TEMP_PATH, "r");
  size_t stagedSize = 0;
  const bool valid = validateBlocklistFile(staged, stagedSize);
  if (staged) staged.close();
  if (!valid) { LittleFS.remove(BLOCKLIST_TEMP_PATH); return false; }

  DnsStateLock state;
  if (!state) { LittleFS.remove(BLOCKLIST_TEMP_PATH); return false; }

  const bool hadActive = LittleFS.exists(BLOCKLIST_PATH);
  if (blocklist) blocklist.close();
  numHashes = 0;
  if (hadActive) {
    LittleFS.remove(BLOCKLIST_BACKUP_PATH);
    if (!LittleFS.rename(BLOCKLIST_PATH, BLOCKLIST_BACKUP_PATH)) {
      reopenBlocklist();
      LittleFS.remove(BLOCKLIST_TEMP_PATH);
      return false;
    }
  }
  if (!LittleFS.rename(BLOCKLIST_TEMP_PATH, BLOCKLIST_PATH)) {
    if (hadActive) LittleFS.rename(BLOCKLIST_BACKUP_PATH, BLOCKLIST_PATH);
    reopenBlocklist();
    LittleFS.remove(BLOCKLIST_TEMP_PATH);
    return false;
  }

  const bool activeOk = reopenBlocklist();
  if (!activeOk) {
    if (blocklist) blocklist.close();
    LittleFS.remove(BLOCKLIST_PATH);
    if (hadActive) LittleFS.rename(BLOCKLIST_BACKUP_PATH, BLOCKLIST_PATH);
    reopenBlocklist();
    return false;
  }
  if (hadActive) LittleFS.remove(BLOCKLIST_BACKUP_PATH);
  return true;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static bool upWriteOk = false;
static size_t upBytes = 0;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.send(401, "text/plain", "login required"); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: invalid blocklist or index capacity exceeded");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = requestHasControlSession();
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; upWriteOk = true; upBytes = 0; beginBlocklistSwap();
      upFile = LittleFS.open(BLOCKLIST_TEMP_PATH, "w");
      if (!upFile) upWriteOk = false;
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile && upWriteOk) {
        size_t written = upFile.write(u.buf, u.currentSize);
        upBytes += written;
        if (written != u.currentSize) upWriteOk = false;
      }
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = upWriteOk && upBytes == u.totalSize && commitNewBlocklist();
      if (!upOk) LittleFS.remove(BLOCKLIST_TEMP_PATH);
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove(BLOCKLIST_TEMP_PATH);
      upWriteOk = false;
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static const uint32_t MAX_UPDATE_INTERVAL_H = 1193;
static bool validBlocklistUrl(const String& url) {
  return !url.length() || (url.length() <= 512 && url.startsWith("https://") && !hasControlCharacter(url));
}
static bool parseUpdateInterval(const String& value, uint32_t* hoursOut) {
  if (!value.length()) return false;
  char* end = nullptr;
  long hours = strtol(value.c_str(), &end, 10);
  if (end == value.c_str() || *end != '\0' || hours < 1 || hours > (long)MAX_UPDATE_INTERVAL_H) return false;
  *hoursOut = (uint32_t)hours;
  return true;
}
static int secureBlocklistGet(HTTPClient& http, WiFiClientSecure& client, const String& initialUrl) {
  String url = initialUrl;
  for (uint8_t redirect = 0; redirect <= 5; redirect++) {
    if (!validBlocklistUrl(url)) return -1;
    if (!http.begin(client, url)) { http.end(); return -1; }
    int code = http.GET();
    if (code == HTTP_CODE_OK) return code;
    const bool isRedirect = code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    String nextUrl = isRedirect ? http.getLocation() : String("");
    http.end();
    if (!isRedirect || !nextUrl.length() || redirect == 5 || !validBlocklistUrl(nextUrl)) return code;
    url = nextUrl;
  }
  return -1;
}

class BoundedFileStream : public Stream {
 public:
  BoundedFileStream(File& file, size_t limit, uint32_t timeoutMs)
      : file_(file), limit_(limit), startedAt_(millis()), timeoutMs_(timeoutMs) {}
  int available() override { return file_.available(); }
  int read() override { return file_.read(); }
  int peek() override { return file_.peek(); }
  void flush() override { file_.flush(); }
  size_t write(uint8_t value) override { return write(&value, 1); }
  size_t write(const uint8_t* data, size_t size) override {
    if (written_ + size > limit_ || millis() - startedAt_ > timeoutMs_) {
      failed_ = true;
      return 0;
    }
    size_t written = file_.write(data, size);
    written_ += written;
    if (written != size) failed_ = true;
    return written;
  }
  size_t written() const { return written_; }
  bool failed() const { return failed_; }
 private:
  File& file_;
  size_t limit_;
  uint32_t startedAt_;
  uint32_t timeoutMs_;
  size_t written_ = 0;
  bool failed_ = false;
};

static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  String savedUrl = f.readStringUntil('\n'); savedUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim();
  f.close();
  updateUrl = validBlocklistUrl(savedUrl) ? savedUrl : String("");
  long savedHours = iv.toInt();
  updateIntervalH = savedHours < 1 ? 1 : savedHours > (long)MAX_UPDATE_INTERVAL_H
      ? MAX_UPDATE_INTERVAL_H : (uint32_t)savedHours;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool syncSystemClock() {
  if (time(nullptr) >= 1704067200) return true;  // 2024-01-01 UTC
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
  const uint32_t startedAt = millis();
  while (millis() - startedAt < 10000UL) {
    if (time(nullptr) >= 1704067200) return true;
    delay(100);
  }
  return false;
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  if (!validBlocklistUrl(url)) { updateStatus = "HTTPS URL required; old list kept"; return false; }
  statusLedFetchNoInternet = WiFi.status() != WL_CONNECTED;
  statusLedFetchingHosts = true;
  if (WiFi.status() != WL_CONNECTED || !syncSystemClock()) {
    updateStatus = "clock or network unavailable; old list kept";
    finishHostFetch(statusLedFetchNoInternet ? StatusLedState::NoInternet : StatusLedState::Failure);
    return false;
  }
  beginBlocklistSwap();
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.useBuiltinCACertBundle();
  HTTPClient http; http.setTimeout(5000);
  const int code = secureBlocklistGet(http, cs, url);
  if (code < 0) {
    updateStatus = "begin failed; old list kept";
    finishHostFetch(statusLedFetchNoInternet ? StatusLedState::NoInternet : StatusLedState::Failure);
    return false;
  }
  if (code != HTTP_CODE_OK) {
    const bool noInternet = code < 0 || WiFi.status() != WL_CONNECTED;
    http.end(); updateStatus = "HTTP " + String(code) + "; old list kept";
    Serial.printf("[remote] %s\n", updateStatus.c_str());
    finishHostFetch(noInternet ? StatusLedState::NoInternet : StatusLedState::Failure);
    return false;
  }
  statusLedFetchNoInternet = false;
  const size_t freeBytes = LittleFS.totalBytes() - LittleFS.usedBytes();
  const size_t availableBytes = freeBytes > 4096 ? freeBytes - 4096 : 0;
  const size_t maxListBytes = (size_t)MAX_INDEXED_HASHES * HASH_BYTES;
  const size_t maxDownload = availableBytes < maxListBytes ? availableBytes : maxListBytes;
  if (!maxDownload) {
    http.end(); updateStatus = "not enough free storage; old list kept";
    finishHostFetch(StatusLedState::Failure);
    return false;
  }
  File f = LittleFS.open(BLOCKLIST_TEMP_PATH, "w");
  if (!f) {
    http.end(); updateStatus = "storage open failed; old list kept";
    finishHostFetch(StatusLedState::Failure);
    return false;
  }
  const int contentLength = http.getSize();
  BoundedFileStream sink(f, maxDownload, 120000UL);
  const int copied = http.writeToStream(&sink);
  const size_t total = sink.written();
  const bool writeOk = copied >= 0 && !sink.failed() &&
                       (contentLength < 0 || total == (size_t)contentLength);
  f.close(); http.end();
  if (!writeOk) {
    LittleFS.remove(BLOCKLIST_TEMP_PATH);
    updateStatus = "download incomplete (" + String(total) + "B); old list kept";
    Serial.printf("[remote] %s\n", updateStatus.c_str());
    finishHostFetch(WiFi.status() == WL_CONNECTED ? StatusLedState::Failure : StatusLedState::NoInternet);
    return false;
  }
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B); old list kept");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  finishHostFetch(ok ? StatusLedState::None : StatusLedState::Failure);
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.send(401, "text/plain", "login required"); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = requestHasControlSession();
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  // Start as station-only. WIFI_AP_STA can restore the previous SoftAP
  // configuration from the Arduino Wi-Fi driver's NVS and broadcast it
  // before the dashboard hotspot setting is checked.
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static String defaultDnsApSsid() {
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ssid[33]; snprintf(ssid, sizeof(ssid), "C6-AdBlock-DNS-%02X%02X", mac[4], mac[5]);
  return String(ssid);
}

static void loadDnsApSettings() {
  String savedSsid, savedPassword;
  bool enabled = true;
  if (prefs.begin("hotspot", true)) {
    savedSsid = prefs.getString("ssid", "");
    savedPassword = prefs.getString("pass", "");
    enabled = prefs.getBool("enabled", true);
    prefs.end();
  }
  if (!savedSsid.length() || savedSsid.length() > 32 || hasControlCharacter(savedSsid))
    savedSsid = defaultDnsApSsid();
  if (savedPassword.length() &&
      (savedPassword.length() < 8 || savedPassword.length() > 63 || hasControlCharacter(savedPassword)))
    savedPassword = "";
  savedSsid.toCharArray(dnsApSsid, sizeof(dnsApSsid));
  dnsApPassword = savedPassword.length() ? savedPassword : String(C6_AP_PASSWORD);
  dnsApEnabled = enabled;
}

static bool saveDnsApSettings(const String& ssid, const String& password, bool enabled) {
  if (!prefs.begin("hotspot", false)) return false;
  bool ok = prefs.putString("ssid", ssid) > 0;
  ok = (prefs.putString("pass", password) > 0) && ok;
  ok = (prefs.putBool("enabled", enabled) > 0) && ok;
  prefs.end();
  return ok;
}

static bool hasControlCharacter(const String& value) {
  for (size_t i = 0; i < value.length(); i++) {
    uint8_t ch = (uint8_t)value[i];
    if (ch < 0x20 || ch == 0x7f) return true;
  }
  return false;
}

static bool validDashboardUser(const String& value) {
  return value.length() > 0 && value.length() <= 32 && !hasControlCharacter(value);
}
static bool validDashboardPass(const String& value) {
  return value.length() > 0 && value.length() <= 63 && !hasControlCharacter(value);
}
static void loadDashboardCredentials() {
  dashboardUser = WEB_USER;
  dashboardPass = WEB_PASS;
  if (!prefs.begin("web_auth", true)) return;
  String credentials = prefs.getString("credentials", "");
  prefs.end();
  int separator = credentials.indexOf('\n');
  if (separator <= 0) return;
  String savedUser = credentials.substring(0, separator);
  String savedPass = credentials.substring(separator + 1);
  if (validDashboardUser(savedUser) && validDashboardPass(savedPass)) {
    dashboardUser = savedUser;
    dashboardPass = savedPass;
  }
}

static uint32_t ipv4Value(IPAddress ip) {
  return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
         ((uint32_t)ip[2] << 8) | (uint32_t)ip[3];
}

static bool apSubnetOverlapsStation(IPAddress candidate, IPAddress staIp, IPAddress staMask) {
  const uint32_t apMask = 0xFFFFFF00UL;  // this AP always serves a /24
  uint32_t apStart = ipv4Value(candidate) & apMask;
  uint32_t apEnd = apStart | ~apMask;
  uint32_t staMaskValue = ipv4Value(staMask);
  uint32_t staStart = ipv4Value(staIp) & staMaskValue;
  uint32_t staEnd = staStart | ~staMaskValue;
  return apStart <= staEnd && staStart <= apEnd;
}

static bool startDnsAccessPoint() {
  dnsApRunning = false;
  if (!dnsApEnabled) return false;
  if (WiFi.status() != WL_CONNECTED) return false;

  // Keep the AP on a different private /24 from the upstream LAN so NAPT routing works.
  const IPAddress candidates[] = {
    IPAddress(192, 168, 4, 1), IPAddress(10, 42, 0, 1),
    IPAddress(172, 29, 0, 1), IPAddress(192, 168, 232, 1)
  };
  IPAddress staIp = WiFi.localIP(), staMask = WiFi.subnetMask();
  bool foundSubnet = false;
  for (const IPAddress& candidate : candidates) {
    if (!apSubnetOverlapsStation(candidate, staIp, staMask)) {
      dnsApIp = candidate;
      foundSubnet = true;
      break;
    }
  }
  if (!foundSubnet) {
    Serial.println("[router] no non-overlapping AP subnet found; DNS AP disabled");
    return false;
  }

  IPAddress apMask(255, 255, 255, 0);
  IPAddress leaseStart(dnsApIp[0], dnsApIp[1], dnsApIp[2], 2);
  if (!WiFi.softAPConfig(dnsApIp, dnsApIp, apMask, leaseStart, dnsApIp)) {
    Serial.println("[router] AP IP/DHCP configuration failed; DNS AP disabled");
    return false;
  }

  uint8_t channel = WiFi.channel();
  if (channel < 1 || channel > 13) channel = 1;
  if (!WiFi.softAP(dnsApSsid, dnsApPassword.c_str(), channel, false, 4)) {
    Serial.println("[router] SoftAP start failed; DNS AP disabled");
    return false;
  }

  esp_netif_t* apNetif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  esp_netif_t* staNetif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (!apNetif || !staNetif || esp_netif_set_default_netif(staNetif) != ESP_OK) {
    Serial.println("[router] network interfaces unavailable; stopping DNS AP");
    WiFi.softAPdisconnect(false);
    return false;
  }
  esp_err_t naptResult = esp_netif_napt_enable(apNetif);
  if (naptResult != ESP_OK) {
    Serial.printf("[router] NAPT enable failed (%s); stopping DNS AP\n", esp_err_to_name(naptResult));
    WiFi.softAPdisconnect(false);
    return false;
  }

  Serial.printf("[router] AP %s at %s; DHCP advertises this device as DNS; NAPT enabled\n",
                dnsApSsid, dnsApIp.toString().c_str());
  dnsApRunning = true;
  return true;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C6 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C6 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c6adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  statusLedSetupPortal = true;
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[32]; snprintf(ap, sizeof(ap), "C6-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP);
  if (!WiFi.softAP(ap)) {
    statusLedCriticalFailure = true;
    Serial.println("[setup] could not start WiFi setup access point");
  }
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  beginStatusLed();
  Serial.println("\n[c6-adblock] booting");
  blockLogBootId = esp_random();
  if (!blockLogBootId) blockLogBootId = 1;
  if (!LittleFS.begin(true)) {
    Serial.println("LittleFS FAILED");
    statusLedCriticalFailure = true;
  }
  recoverBlocklistSwap();
  recoverBannedSwap();
  const bool blocklistOk = reopenBlocklist();
  settleBlocklistBackup(blocklistOk);
  Serial.printf("blocklist: %u domains\n", numHashes);

  // Hold BOOT at power-on to clear all saved settings; keep firmware and blocklist.
  const int BOOT_PIN = 9;     // BOOT button on ESP32-C6-DevKitC-1
  pinMode(BOOT_PIN, INPUT_PULLUP);
  bool resetHeld = digitalRead(BOOT_PIN) == LOW;
  if (resetHeld) { delay(60); resetHeld = digitalRead(BOOT_PIN) == LOW; }
  if (resetHeld) {
    if (clearAllConfiguration()) Serial.println("[setup] BOOT held -> cleared all saved settings");
    else Serial.println("[setup] BOOT held -> could not clear all saved settings");
  }

  loadCustom(); loadBanned(); loadUpdateCfg();
  loadDashboardCredentials();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  loadDnsApSettings();
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("c6adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c6adblock.local"); }

  if (dashboardPass == "CHANGE_ME_WEB_PASSWORD" ||
      strcmp(dnsApPassword.c_str(), "CHANGE_ME_AP_PASSWORD") == 0)
    Serial.println("[WARN] default dashboard or hotspot credentials are active "
                    "(default values are public in the example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.onPacket(onClientDnsPacket);
  upstreamCli.onPacket(onUpstreamPacket);
  bool dnsReady = dnsServer.listen(DNS_PORT);
  bool upstreamReady = upstreamCli.listen(0);
  dnsStateMutex = xSemaphoreCreateMutex();
  Serial.printf("AsyncUDP DNS :53 %s, upstream socket %s\n",
                dnsReady ? "ready" : "FAILED", upstreamReady ? "ready" : "FAILED");
  if (!dnsReady || !upstreamReady || !dnsStateMutex) statusLedCriticalFailure = true;
  if (dnsReady && upstreamReady && dnsStateMutex &&
      xTaskCreate(dnsProcessingTask, "dns-worker", 8192, nullptr, tskIDLE_PRIORITY + 1, nullptr) != pdPASS)
    statusLedCriticalFailure = true;
  if (dnsReady && upstreamReady) {
    if (dnsApEnabled) startDnsAccessPoint();
    else Serial.println("[router] DNS access point disabled in dashboard settings");
  }
  { const char* hdrs[] = { CSRF_HEADER, "Cookie" }; web.collectHeaders(hdrs, 2); }
  web.on("/", handleDashboardRoot);
  web.on("/login", HTTP_POST, handleLogin);
  web.on("/logout", HTTP_POST, handleLogout);
  web.on("/dashboard-credentials", HTTP_POST, handleDashboardCredentials);
  web.on("/reset-config", HTTP_POST, handleResetConfig);
  web.on("/stats.json", handleStats);
  web.on("/hotspot", HTTP_POST, handleHotspotSave);
  web.on("/wifi", HTTP_POST, handleWifiUpdate);
  web.on("/events.json", handleBlockedEvents);
  web.on("/ban", handleBan);
  web.on("/addblock", []() {
    if (!requireAuth()) return;
    DnsStateLock state;
    if (!state) { web.send(503, "text/plain", "DNS state unavailable"); return; }
    bool added = addCustom(web.arg("d"));
    state.unlock();
    web.send(added ? 200 : 400, "text/plain", added ? "ok" : "invalid, duplicate, or full custom list");
  });
  web.on("/unblock", []() {
    if (!requireAuth()) return;
    DnsStateLock state;
    if (!state) { web.send(503, "text/plain", "DNS state unavailable"); return; }
    bool removed = removeCustom(web.arg("d"));
    state.unlock();
    web.send(removed ? 200 : 404, "text/plain", removed ? "ok" : "custom domain not found");
  });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    DnsStateLock state;
    if (!state) { web.send(503, "text/plain", "DNS state unavailable"); return; }
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    state.unlock();
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() {
    if (!requireAuth()) return;
    DnsStateLock state;
    if (!state) { web.send(503, "text/plain", "DNS state unavailable"); return; }
    blockingOn = true; resumeAt = 0;
    state.unlock();
    web.send(200, "text/plain", "resumed");
  });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() {
    if (!requireAuth()) return;
    String nextUrl = updateUrl;
    uint32_t nextInterval = updateIntervalH;
    if (web.hasArg("u")) {
      nextUrl = web.arg("u"); nextUrl.trim();
      if (!validBlocklistUrl(nextUrl)) { web.send(400, "text/plain", "an HTTPS blocklist URL is required"); return; }
    }
    if (web.hasArg("h") && !parseUpdateInterval(web.arg("h"), &nextInterval)) {
      web.send(400, "text/plain", "update interval must be 1-1193 hours"); return;
    }
    updateUrl = nextUrl; updateIntervalH = nextInterval;
    saveUpdateCfg();
    fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus);
  });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    String nextUrl = updateUrl;
    uint32_t nextInterval = updateIntervalH;
    if (web.hasArg("u")) { nextUrl = web.arg("u"); nextUrl.trim(); }
    if (!validBlocklistUrl(nextUrl)) { web.send(400, "text/plain", "an HTTPS blocklist URL is required"); return; }
    if (web.hasArg("h") && !parseUpdateInterval(web.arg("h"), &nextInterval)) {
      web.send(400, "text/plain", "update interval must be 1-1193 hours"); return;
    }
    updateUrl = nextUrl; updateIntervalH = nextInterval;
    saveUpdateCfg(); updateStatus = updateUrl.length() ? "configured" : "no url set"; web.send(200, "text/plain", "ok");
  });
  web.begin();
  Serial.println("DNS :53 + dashboard :80 up");
}

void loop() {
  web.handleClient();
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  delay(1);
}
