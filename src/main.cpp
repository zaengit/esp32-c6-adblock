// ESP32 AdBlock — DNS sinkhole + web dashboard (no PSRAM required).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
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
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

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
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 8192;   // 40 KB index; supports up to ~2.08M hashes
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket
static const uint32_t MAX_INDEXED_HASHES = (INDEX_ENTRIES - 1) * (MAX_RANGE - 1) + 1;
static const int DNS_CACHE_SIZE = 8;
static const int DNS_PENDING_MAX = 32;
static const int DNS_MAX_QUESTION = 260;
static const int DNS_RX_QUEUE_SIZE = 128;
static const int UPSTREAM_RX_QUEUE_SIZE = 32;
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

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct DnsCacheEntry {
  uint8_t packet[1536];
  uint16_t packetLen = 0;
  uint16_t requestLen = 0;
  uint16_t questionLen = 0;
  uint64_t queryKey = 0;
  uint32_t expiresAt = 0;
  bool valid = false;
};
static DnsCacheEntry dnsCache[DNS_CACHE_SIZE];
static uint8_t dnsCacheNext = 0;

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

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
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
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
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
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
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
  if (ttl > DNS_CACHE_MAX_AGE_MS / 1000) ttl = DNS_CACHE_MAX_AGE_MS / 1000;
  e.expiresAt = millis() + ttl * 1000UL;
  e.valid = true;
}

template<size_t N>
static void enqueueDatagram(DnsDatagram (&queue)[N], uint8_t& head,
                            uint8_t& count, uint32_t& drops,
                            AsyncUDPPacket& packet) {
  size_t len = packet.length();
  if (len == 0 || len > sizeof(buf)) {
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
  if (count >= N) {
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
  portEXIT_CRITICAL(&dnsRxMux);
}

template<size_t N>
static bool dequeueDatagram(DnsDatagram (&queue)[N], uint8_t& tail,
                            uint8_t& count, IPAddress* ip, uint16_t* port,
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
    found = true;
  }
  portEXIT_CRITICAL(&dnsRxMux);
  if (found) { memcpy(data, packetData, *len); free(packetData); }
  return found;
}

static void onClientDnsPacket(AsyncUDPPacket& packet) {
  enqueueDatagram(dnsRxQueue, dnsRxHead, dnsRxCount, dnsRxDrops, packet);
}

static void onUpstreamPacket(AsyncUDPPacket& packet) {
  enqueueDatagram(upstreamRxQueue, upstreamRxHead, upstreamRxCount, upstreamRxDrops, packet);
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
    if (!dequeueDatagram(upstreamRxQueue, upstreamRxTail, upstreamRxCount,
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

// Process a bounded burst without waiting for upstream replies; pollUpstream() handles
// completions and timeouts from loop(), so web, OTA, and other DNS clients keep running.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    // Keep unprocessed client packets queued while all upstream slots are busy.
    // This avoids returning SERVFAIL just because a short burst filled the
    // asynchronous request table; pollUpstream() frees slots on the next loop.
    if (!hasPendingSlot()) break;
    IPAddress cip; uint16_t cport = 0; uint16_t qlen = 0;
    if (!dequeueDatagram(dnsRxQueue, dnsRxTail, dnsRxCount, &cip, &cport, &qlen, buf)) break;
    did = true;
    if (qlen < 12) continue;

    char domain[256]; uint16_t qtype = 0; int qend = 0;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    if (qend < 17 || qend > qlen) { sendDnsReply(cip, cport, buildServFail(0)); continue; }

    Dev* c = getClient((uint32_t)cip);
    bool ban = c && c->banned;
    const char* blockReason = ban ? "client" : nullptr;
    bool blocked = ban || (blockingOn && dl && numHashes && isBlocked(domain, &blockReason));
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
      totalAllowed++; if (c) c->allowed++;
      if (!queued) sendDnsReply(cip, cport, buildServFail(qend));
    }
  }
  return did;
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

static void handleStats() {
  uint32_t up = millis() / 1000;
  uint32_t clientDrops, upstreamDrops;
  portENTER_CRITICAL(&dnsRxMux);
  clientDrops = dnsRxDrops; upstreamDrops = upstreamRxDrops;
  portEXIT_CRITICAL(&dnsRxMux);
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"dns_rx_drops\":" + String(clientDrops) + ",\"upstream_rx_drops\":" + String(upstreamDrops) +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.sendHeader("Cache-Control", "no-store");
  web.send(200, "application/json", j);
}

// Short polling keeps the single-threaded WebServer loop available to DNS.
// An open SSE response would hold that loop while the browser stays connected.
static void handleBlockedEvents() {
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
  web.sendHeader("Cache-Control", "no-store");
  web.send(200, "application/json", json);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c6adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c6-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  uint32_t count = blocklist ? blocklist.size() / HASH_BYTES : 0;
  if (count > MAX_INDEXED_HASHES) {
    Serial.printf("[blocklist] %u hashes exceed index capacity %u; forwarding without blocking\n",
                  count, MAX_INDEXED_HASHES);
    blocklist.close(); numHashes = 0;
    return;
  }
  numHashes = count;
  buildFlashIndex();
}
static void beginBlocklistSwap() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0 && (sz / HASH_BYTES) <= MAX_INDEXED_HASHES;
  if (ok) ok = LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  if (!ok) LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: invalid blocklist or index capacity exceeded");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
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
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
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
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[32]; snprintf(ap, sizeof(ap), "C6-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
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
  Serial.println("\n[c6-adblock] booting");
  blockLogBootId = esp_random();
  if (!blockLogBootId) blockLogBootId = 1;
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  reopenBlocklist();
  Serial.printf("blocklist: %u domains\n", numHashes);
  loadCustom(); loadBanned(); loadUpdateCfg();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
  const int BOOT_PIN = 9;     // BOOT button on ESP32-C6-DevKitC-1
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("c6adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c6adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.onPacket(onClientDnsPacket);
  upstreamCli.onPacket(onUpstreamPacket);
  bool dnsReady = dnsServer.listen(DNS_PORT);
  bool upstreamReady = upstreamCli.listen(0);
  Serial.printf("AsyncUDP DNS :53 %s, upstream socket %s\n",
                dnsReady ? "ready" : "FAILED", upstreamReady ? "ready" : "FAILED");
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/events.json", handleBlockedEvents);
  web.on("/ban", handleBan);
  web.on("/addblock", []() { if (!requireAuth()) return; addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("c6adblock");   // pio run -e c6 -t upload --upload-port c6adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = pollUpstream();
  busy = handleDns() || busy;
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
