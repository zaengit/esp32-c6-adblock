#pragma once
// Copy this file to secrets.h and fill in your WiFi credentials.
// secrets.h is gitignored so your credentials never get committed.
static const char* WIFI_SSID = "YOUR_WIFI_SSID";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// Initial password for the C6-AdBlock-DNS-XXXX WiFi network. The dashboard can
// later change the hotspot SSID and password without reflashing firmware.
#define C6_AP_PASSWORD "CHANGE_ME_AP_PASSWORD"

// Initial dashboard login. Credentials can be changed later from Device
// Management after signing in. Pick a real password, not your WiFi password.
static const char* WEB_USER = "admin";
static const char* WEB_PASS = "CHANGE_ME_WEB_PASSWORD";
