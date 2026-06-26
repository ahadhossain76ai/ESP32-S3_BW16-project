// packet-injection.cpp — Enhanced BW16 firmware for 5GHz operations
#include "packet-injection.h"
#include <WiFi.h>
#include <WiFiUdp.h>

static WiFiUDP repeater_udp;
static bool repeater_mode = false;

void handle_serial_commands() {
    if (Serial.available() > 0) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        
        if (cmd.startsWith("PING")) {
            Serial.println("PONG");
        }
        else if (cmd.startsWith("SCAN 5GHZ")) {
            int n = WiFi.scanNetworks();
            Serial.println("{\"networks\":[");
            for (int i = 0; i < n; i++) {
                if (i > 0) Serial.println(",");
                Serial.printf("{\"ssid\":\"%s\"", WiFi.SSID(i).c_str());
                uint8_t *bssid = WiFi.BSSID(i);
                Serial.printf(",\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\"",
                    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                Serial.printf(",\"channel\":%d", WiFi.channel(i));
                Serial.printf(",\"rssi\":%d", WiFi.RSSI(i));
                Serial.printf(",\"encryption\":\"%s\"",
                    WiFi.encryptionType(i) == ENC_TYPE_NONE ? "OPEN" : "WPA2");
                Serial.print("}");
            }
            Serial.println("]}");
            WiFi.scanDelete();
        }
        else if (cmd.startsWith("REPEATER START")) {
            String rest = cmd.substring(14);
            int space = rest.indexOf(' ');
            String ssid = rest.substring(0, space);
            String pass = rest.substring(space + 1);
            
            repeater_mode = true;
            
            WiFi.mode(WIFI_MODE_STA);
            WiFi.begin(ssid.c_str(), pass.c_str());
            
            int attempts = 0;
            while (WiFi.status() != WL_CONNECTED && attempts < 20) {
                delay(500);
                attempts++;
            }
            
            if (WiFi.status() == WL_CONNECTED) {
                Serial.printf("{\"status\":\"Connected to %s\",\"ip\":\"%s\"}",
                    ssid.c_str(), WiFi.localIP().toString().c_str());
                
                WiFi.mode(WIFI_MODE_APSTA);
                WiFi.softAPConfig(IPAddress(192,168,1,1), IPAddress(192,168,1,1), IPAddress(255,255,255,0));
                WiFi.softAP("H4CK3R_Repeater", "hack3r123", 1, 0, 8);
                
                Serial.println("{\"status\":\"Repeater AP ready at 192.168.1.1\"}");
            } else {
                Serial.println("{\"error\":\"Failed to connect\"}");
            }
        }
        else if (cmd.startsWith("REPEATER STOP")) {
            repeater_mode = false;
            WiFi.disconnect();
            WiFi.softAPdisconnect(true);
            Serial.println("{\"status\":\"Repeater stopped\"}");
        }
    }
}
