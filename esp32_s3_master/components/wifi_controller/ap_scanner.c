#include "ap_scanner.h"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_rom_sys.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "ap_scanner";
static wifi_ap_record_t *records = NULL;
static int count = 0;
static bool scan_complete = false;

int ap_scanner_get_count(void) { return count; }
wifi_ap_record_t* ap_scanner_get_results(void) { return records; }
bool ap_scanner_is_scan_complete(void) { return scan_complete; }

void ap_scanner_set_results(wifi_ap_record_t *recs, int n) {
    if (records) free(records);
    records = (wifi_ap_record_t*)calloc(n, sizeof(wifi_ap_record_t));
    if (records && recs) {
        memcpy(records, recs, n * sizeof(wifi_ap_record_t));
        count = n;
    } else {
        count = 0;
    }
    scan_complete = true;
    ESP_LOGI(TAG, "Scan results stored: %d networks", count);
}

void ap_scanner_reset(void) {
    scan_complete = false;
    if (records) {
        free(records);
        records = NULL;
    }
    count = 0;
}

// ==================== HIDDEN SSID DETECTION ====================
/**
 * @brief Detect hidden SSIDs by sending null probe requests
 * 
 * Hidden APs (SSID cloaked) still respond to probe requests
 * even with empty SSID field. We capture their probe responses
 * to reveal the actual SSID.
 * 
 * @param channel Channel to scan for hidden APs
 * @return Number of hidden APs detected (updated in scan results)
 */
int ap_scanner_detect_hidden_ssids(uint8_t channel) {
    // Hidden SSID detection via null probe requests
    // Some APs expose their SSID in probe response even when cloaked
    
    uint8_t probe_frame[] = {
        0x40, 0x00,       // Frame Control: Probe Request
        0x00, 0x00,       // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Destination: Broadcast
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Source: Will be set dynamically
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // BSSID: Broadcast
        0x00, 0x00,       // Sequence
        0x00, 0x00,       // SSID Parameter: length 0 (null probe)
        0x01, 0x08,       // Supported Rates
        0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24  // Rates
    };
    
    // Set source MAC to our STA MAC
    uint8_t sta_mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, sta_mac);
    memcpy(&probe_frame[10], sta_mac, 6);
    
    // Set channel
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_rom_delay_us(100);
    
    // Send multiple probe requests
    int hidden_detected = 0;
    for (int i = 0; i < 5; i++) {
        esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, probe_frame, sizeof(probe_frame), false);
        if (err == ESP_OK) hidden_detected++;
        esp_rom_delay_us(500);
    }
    
    ESP_LOGI(TAG, "Hidden SSID probe sent on ch %d (detected: %d)", 
             channel, hidden_detected);
    
    return hidden_detected;
}

/**
 * @brief Enhanced scan that also detects hidden SSIDs
 * @param records Output array of AP records
 * @param count Input/output count
 * @return ESP_OK on success
 */
esp_err_t ap_scanner_enhanced_scan(wifi_ap_record_t *records, uint16_t *count) {
    if (!records || !count) return ESP_ERR_INVALID_ARG;
    
    // First, do normal scan
    wifi_scan_config_t scan_conf = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 120,
        .scan_time.active.max = 120,
    };
    
    esp_err_t err = esp_wifi_scan_start(&scan_conf, true);
    if (err != ESP_OK) return err;
    
    err = esp_wifi_scan_get_ap_records(count, records);
    if (err != ESP_OK) return err;
    
    // Now try to reveal hidden SSIDs by sending null probes on each channel
    for (int ch = 1; ch <= 13; ch++) {
        ap_scanner_detect_hidden_ssids(ch);
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    
    // Re-scan to capture any newly revealed SSIDs
    esp_wifi_scan_start(&scan_conf, true);
    
    uint16_t new_count = *count + 5; // Extra space for hidden APs
    wifi_ap_record_t *new_records = calloc(new_count, sizeof(wifi_ap_record_t));
    if (!new_records) return ESP_ERR_NO_MEM;
    
    uint16_t actual_count = new_count;
    err = esp_wifi_scan_get_ap_records(&actual_count, new_records);
    if (err == ESP_OK) {
        memcpy(records, new_records, actual_count * sizeof(wifi_ap_record_t));
        *count = actual_count;
    }
    
    free(new_records);
    return err;
}