#include "wifi_controller.h"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_event.h"
#include <string.h>

static const char *TAG = "wifi_controller";
static bool wifi_init = false;
static bool sta_connected = false;
static uint8_t original_mac_ap[6];

// Event handler for STA connection status
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
            case WIFI_EVENT_STA_START:
                ESP_LOGI(TAG, "STA started");
                break;
                
            case WIFI_EVENT_STA_CONNECTED:
                ESP_LOGI(TAG, "STA connected to AP");
                break;
                
            case WIFI_EVENT_STA_DISCONNECTED: {
                wifi_event_sta_disconnected_t* disconnected = 
                    (wifi_event_sta_disconnected_t*) event_data;
                ESP_LOGW(TAG, "STA disconnected. Reason: %d", disconnected->reason);
                sta_connected = false;
                break;
            }
                
            case WIFI_EVENT_AP_START:
                ESP_LOGI(TAG, "SoftAP started");
                break;
                
            case WIFI_EVENT_AP_STOP:
                ESP_LOGI(TAG, "SoftAP stopped");
                break;
                
            default:
                break;
        }
    } else if (event_base == IP_EVENT) {
        if (event_id == IP_EVENT_STA_GOT_IP) {
            ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
            ESP_LOGI(TAG, "STA Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
            sta_connected = true;
        }
    }
}

static void wifi_init_apsta(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    
    // Create event loop if not already created
    esp_event_loop_create_default();
    
    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();
    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    // Register event handlers
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));
    
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, original_mac_ap));
    ESP_ERROR_CHECK(esp_wifi_start());
    wifi_init = true;
    
    ESP_LOGI(TAG, "WiFi initialized in AP+STA mode");
}

void wifictl_ap_start(wifi_config_t *wifi_config) {
    if (!wifi_init) wifi_init_apsta();
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, wifi_config));
    ESP_LOGI(TAG, "AP started: %s", wifi_config->ap.ssid);
}

void wifictl_ap_stop(void) {
    wifi_config_t cfg = { .ap = { .max_connection = 0 } };
    esp_wifi_set_config(WIFI_IF_AP, &cfg);
    ESP_LOGI(TAG, "AP stopped");
}

void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]) {
    if (!wifi_init) wifi_init_apsta();
    
    wifi_config_t sta_cfg = {0};
    sta_cfg.sta.channel = ap_record->primary;
    sta_cfg.sta.scan_method = WIFI_FAST_SCAN;
    sta_cfg.sta.pmf_cfg.capable = false;
    sta_cfg.sta.pmf_cfg.required = false;
    memcpy(sta_cfg.sta.ssid, ap_record->ssid, 32);
    if (password) {
        memcpy(sta_cfg.sta.password, password, strlen(password) + 1);
    }
    
    // Sortie ensure APSTA mode
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_cfg));
    ESP_ERROR_CHECK(esp_wifi_connect());
    
    ESP_LOGI(TAG, "STA connecting to: %s (ch %d)", ap_record->ssid, ap_record->primary);
}

/**
 * @brief Connect STA to home router by SSID/password (after scanning)
 * This keeps the SoftAP running simultaneously
 */
static esp_event_handler_t s_scan_done_handler = NULL;

void wifictl_set_scan_done_handler(esp_event_handler_t handler) {
    s_scan_done_handler = handler;
}

bool wifictl_sta_connect_home(const char *ssid, const char *pass) {
    if (!wifi_init) wifi_init_apsta();

    // attack handler সরাও
    if (s_scan_done_handler)
        esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, s_scan_done_handler);

    wifi_scan_config_t scan_cfg = {
        .ssid        = (uint8_t *)ssid,
        .channel     = 0,
        .show_hidden = true,
        .scan_type   = WIFI_SCAN_TYPE_ACTIVE,
    };

    uint8_t channel = 0;
    if (esp_wifi_scan_start(&scan_cfg, true) == ESP_OK) {
        uint16_t count = 10;
        wifi_ap_record_t records[10];
        if (esp_wifi_scan_get_ap_records(&count, records) == ESP_OK) {
            for (int i = 0; i < count; i++) {
                if (strcmp((char *)records[i].ssid, ssid) == 0) {
                    channel = records[i].primary;
                    break;
                }
            }
        }
    }

    // attack handler ফিরিয়ে দাও
    if (s_scan_done_handler)
        esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, s_scan_done_handler, NULL);

    wifi_config_t sta_cfg = {0};
    sta_cfg.sta.channel     = channel;
    sta_cfg.sta.scan_method = channel ? WIFI_FAST_SCAN : WIFI_ALL_CHANNEL_SCAN;
    sta_cfg.sta.pmf_cfg.capable  = false;
    sta_cfg.sta.pmf_cfg.required = false;
    strncpy((char *)sta_cfg.sta.ssid, ssid, sizeof(sta_cfg.sta.ssid) - 1);
    if (pass && strlen(pass) > 0)
        strncpy((char *)sta_cfg.sta.password, pass, sizeof(sta_cfg.sta.password) - 1);

    esp_wifi_disconnect();
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_cfg));
    ESP_ERROR_CHECK(esp_wifi_connect());

    nvs_handle_t nvs;
    if (nvs_open("storage", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_set_str(nvs, "sta_ssid", ssid);
        if (pass) nvs_set_str(nvs, "sta_pass", pass);
        nvs_commit(nvs);
        nvs_close(nvs);
    }

    return true;
}

bool wifictl_sta_is_connected(void) {
    return sta_connected;
}

void wifictl_sta_disconnect(void) {
    esp_wifi_disconnect();
    sta_connected = false;
    ESP_LOGI(TAG, "STA disconnected");
}

void wifictl_set_ap_mac(const uint8_t *mac_ap) {
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, mac_ap));
}

void wifictl_get_ap_mac(uint8_t *mac_ap) {
    esp_wifi_get_mac(WIFI_IF_AP, mac_ap);
}

void wifictl_restore_ap_mac(void) {
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, original_mac_ap));
}

void wifictl_get_sta_mac(uint8_t *mac_sta) {
    esp_wifi_get_mac(WIFI_IF_STA, mac_sta);
}

void wifictl_set_channel(uint8_t channel) {
    if (channel < 1 || channel > 13) return;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void wifictl_get_mgmt_creds(char* ssid, char* pass) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        size_t s_len = 32, p_len = 64;
        if (nvs_get_str(nvs, "ap_ssid", ssid, &s_len) != ESP_OK) strcpy(ssid, "hydra");
        if (nvs_get_str(nvs, "ap_pass", pass, &p_len) != ESP_OK) strcpy(pass, "notforfun");
        nvs_close(nvs);
    } else {
        strcpy(ssid, "hydra");
        strcpy(pass, "notforfun");
    }
}

void wifictl_get_sta_creds(char* ssid, char* pass) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        size_t s_len = 32, p_len = 64;
        if (nvs_get_str(nvs, "sta_ssid", ssid, &s_len) != ESP_OK) ssid[0] = 0;
        if (nvs_get_str(nvs, "sta_pass", pass, &p_len) != ESP_OK) pass[0] = 0;
        nvs_close(nvs);
    } else {
        ssid[0] = 0;
        pass[0] = 0;
    }
}

void wifictl_mgmt_ap_start(void) {
    char ssid[32] = {0}, pass[64] = {0};
    wifictl_get_mgmt_creds(ssid, pass);
    
    wifi_config_t cfg = {
        .ap = {
            .ssid_len = strlen(ssid),
            .channel = 1,
            .max_connection = 4,
            .authmode = (strlen(pass) >= 8) ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN,
        },
    };
    memcpy(cfg.ap.ssid, ssid, 32);
    memcpy(cfg.ap.password, pass, 64);
    wifictl_ap_start(&cfg);
    ESP_LOGI(TAG, "Management AP started: SSID=%s, IP=192.168.4.1", ssid);
}

void wifictl_mgmt_ap_stop(void) {
    wifictl_ap_stop();
}

/**
 * @brief Try to auto-connect to saved home router on boot
 * This keeps SoftAP running AND connects STA
 */
void wifictl_auto_connect_saved(void) {
    char sta_ssid[32] = {0};
    char sta_pass[64] = {0};
    
    wifictl_get_sta_creds(sta_ssid, sta_pass);
    
    if (strlen(sta_ssid) > 0) {
        ESP_LOGI(TAG, "Auto-connecting to saved home router: %s", sta_ssid);
        
        // Ensure APSTA mode
        if (!wifi_init) wifi_init_apsta();
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
        
        // Connect without scanning (use saved config)
        wifi_config_t sta_cfg = {0};
        sta_cfg.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
        sta_cfg.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
        sta_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
        sta_cfg.sta.pmf_cfg.capable = false;
        sta_cfg.sta.pmf_cfg.required = false;
        memcpy(sta_cfg.sta.ssid, sta_ssid, strlen(sta_ssid));
        if (strlen(sta_pass) > 0) {
            memcpy(sta_cfg.sta.password, sta_pass, strlen(sta_pass) + 1);
        }
        
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_cfg));
        ESP_ERROR_CHECK(esp_wifi_connect());
    } else {
        ESP_LOGI(TAG, "No saved home router credentials");
    }
}
