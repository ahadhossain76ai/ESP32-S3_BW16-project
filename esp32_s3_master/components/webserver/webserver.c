/*
 * webserver.c — H4CK3R v2.0 HTTP API Server
 * ESP32-S3 + BW16 RTL8720DN WiFi Pentest Platform
 * 
 * Updated: EvilTwin phishing_page support, DevilTwin/Fishing_Web serving
 */

#include "webserver.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "attack_deauth.h"
#include "attack_eviltwin.h"
#include "attack_beacon_spam.h"
#include "attack_jammer.h"
#include "attack_ducky.h"
#include "attack_pmkid.h"
#include "attack.h"
#include "bw16_uart.h"
#include "ap_scanner.h"
#include "wifi_pass_verifier.h"
#include <esp_http_server.h>
#include <esp_spiffs.h>
#include <esp_log.h>
#include <esp_system.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <dirent.h>
#include <cJSON.h>

static const char *TAG = "WEBSERVER";
static httpd_handle_t server = NULL;

#define MAX_SCRATCH_BUF 8192
#define MAX_FILE_SIZE (512 * 1024)
#define SPIFFS_BASE_PATH "/spiffs"

// ==================== GLOBALS FOR PHISHING PAGES ====================
static char g_current_phishing_page[64] = {0};  // e.g. "DevilTwin/EvilTwin_tp_link.html"

void set_active_phishing_page(const char *path) {
    if (path) {
        strncpy(g_current_phishing_page, path, sizeof(g_current_phishing_page) - 1);
        g_current_phishing_page[sizeof(g_current_phishing_page) - 1] = '\0';
        ESP_LOGI(TAG, "📄 Active phishing page set to: %s", g_current_phishing_page);
    } else {
        g_current_phishing_page[0] = '\0';
        ESP_LOGI(TAG, "📄 Active phishing page cleared");
    }
}

// ==================== HELPER FUNCTIONS ====================

static esp_err_t send_json(httpd_req_t *req, cJSON *root) {
    char *str = cJSON_Print(root);
    if (!str) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON error");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, str);
    free(str);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t send_error(httpd_req_t *req, const char *msg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "error", msg);
    return send_json(req, root);
}

static esp_err_t send_status(httpd_req_t *req, const char *msg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", msg);
    return send_json(req, root);
}

// Extract query parameter value
static char* get_query_param(const char *query, const char *param) {
    if (!query || !param) return NULL;
    char *q = strdup(query);
    if (!q) return NULL;
    char *tok = strtok(q, "&");
    while (tok) {
        char *eq = strchr(tok, '=');
        if (eq) {
            *eq = '\0';
            if (strcmp(tok, param) == 0) {
                char *val = strdup(eq + 1);
                char *src = val, *dst = val;
                while (*src) {
                    if (*src == '%' && *(src+1) && *(src+2)) {
                        char hex[3] = {src[1], src[2], 0};
                        *dst++ = (char)strtol(hex, NULL, 16);
                        src += 3;
                    } else if (*src == '+') {
                        *dst++ = ' '; src++;
                    } else {
                        *dst++ = *src++;
                    }
                }
                *dst = '\0';
                free(q);
                return val;
            }
        }
        tok = strtok(NULL, "&");
    }
    free(q);
    return NULL;
}

// ==================== API: STATUS ====================
static esp_err_t api_status_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "esp32", "Online");
    cJSON_AddStringToObject(root, "bw16", bw16_is_connected() ? "Connected" : "Disconnected");
    cJSON_AddStringToObject(root, "mode", "AP+STA");
    
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    cJSON_AddNumberToObject(root, "wifi_mode", mode);
    
    wifi_config_t conf;
    esp_wifi_get_config(WIFI_IF_AP, &conf);
    cJSON_AddStringToObject(root, "ap_ssid", (const char*)conf.ap.ssid);
    cJSON_AddStringToObject(root, "ip", "192.168.4.1");
    
    size_t total = 0, used = 0;
    esp_spiffs_info(NULL, &total, &used);
    char spiffs_str[32];
    snprintf(spiffs_str, sizeof(spiffs_str), "%u / %u KB", (unsigned)(total-used)/1024, (unsigned)total/1024);
    cJSON_AddStringToObject(root, "spiffs_free", spiffs_str);
    
    char uptime[32];
    uint64_t uptime_ms = esp_timer_get_time() / 1000;
    snprintf(uptime, sizeof(uptime), "%llum %llus", uptime_ms/60000, (uptime_ms/1000)%60);
    cJSON_AddStringToObject(root, "uptime", uptime);
    
    return send_json(req, root);
}

// ==================== SCAN API ====================
static esp_err_t api_scan_all_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateObject();
    cJSON *networks_24 = cJSON_AddArrayToObject(root, "networks_24");
    cJSON *networks_5 = cJSON_AddArrayToObject(root, "networks_5");
    
    // 2.4GHz scan (native ESP32)
    wifi_scan_config_t scan_conf = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 120,
        .scan_time.active.max = 120,
    };
    
    if (esp_wifi_scan_start(&scan_conf, true) == ESP_OK) {
        uint16_t count = 0;
        esp_wifi_scan_get_ap_num(&count);
        wifi_ap_record_t *records = malloc(count * sizeof(wifi_ap_record_t));
        if (records && esp_wifi_scan_get_ap_records(&count, records) == ESP_OK) {
            for (int i = 0; i < count; i++) {
                cJSON *n = cJSON_CreateObject();
                cJSON_AddStringToObject(n, "ssid", (char*)records[i].ssid);
                char bssid_str[18];
                snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    records[i].bssid[0], records[i].bssid[1], records[i].bssid[2],
                    records[i].bssid[3], records[i].bssid[4], records[i].bssid[5]);
                cJSON_AddStringToObject(n, "bssid", bssid_str);
                cJSON_AddNumberToObject(n, "channel", records[i].primary);
                cJSON_AddNumberToObject(n, "rssi", records[i].rssi);
                cJSON_AddBoolToObject(n, "is_5ghz", false);
                cJSON_AddItemToArray(networks_24, n);
            }
            free(records);
        }
    }
    
    // 5GHz scan (via BW16) — bw16_scan_5ghz() is void, sends command via UART
    bw16_scan_5ghz();
    
    // Add placeholder message — actual 5GHz results retrieved separately
    cJSON *n_5 = cJSON_CreateObject();
    cJSON_AddStringToObject(n_5, "ssid", "(5GHz scan initiated via BW16)");
    cJSON_AddNumberToObject(n_5, "channel", 0);
    cJSON_AddNumberToObject(n_5, "rssi", 0);
    cJSON_AddBoolToObject(n_5, "is_5ghz", true);
    cJSON_AddItemToArray(networks_5, n_5);
    
    cJSON_AddNumberToObject(root, "count", cJSON_GetArraySize(networks_24) + cJSON_GetArraySize(networks_5));
    return send_json(req, root);
}

static esp_err_t api_scan_stop_handler(httpd_req_t *req) {
    esp_wifi_scan_stop();
    return send_status(req, "Scan stopped");
}

static esp_err_t api_scan_handler(httpd_req_t *req) {
    const char *query = strchr(req->uri, '?');
    char *type = get_query_param(query, "type");
    
    // FULL SCAN (2.4GHz + 5GHz)
    if (type && strcmp(type, "full") == 0) {
        free(type);
        return api_scan_all_handler(req);
    }
    
    // HIDDEN SCAN
    if (type && strcmp(type, "hidden") == 0) {
        free(type);
        uint16_t count = 10;
        wifi_ap_record_t records[10];
        
        wifi_scan_config_t scan_conf = {
            .ssid = NULL,
            .bssid = NULL,
            .channel = 0,
            .show_hidden = true,
            .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        };
        
        if (esp_wifi_scan_start(&scan_conf, true) == ESP_OK) {
            esp_wifi_scan_get_ap_num(&count);
            if (count > 10) count = 10;
            esp_wifi_scan_get_ap_records(&count, records);
        } else {
            count = 0;
        }
        
        cJSON *root = cJSON_CreateObject();
        cJSON *nets = cJSON_AddArrayToObject(root, "networks");
        for (int i = 0; i < count; i++) {
            cJSON *n = cJSON_CreateObject();
            cJSON_AddStringToObject(n, "ssid", (char*)records[i].ssid);
            char bssid_str[18];
            snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                records[i].bssid[0], records[i].bssid[1], records[i].bssid[2],
                records[i].bssid[3], records[i].bssid[4], records[i].bssid[5]);
            cJSON_AddStringToObject(n, "bssid", bssid_str);
            cJSON_AddNumberToObject(n, "channel", records[i].primary);
            cJSON_AddNumberToObject(n, "rssi", records[i].rssi);
            cJSON_AddItemToArray(nets, n);
        }
        return send_json(req, root);
    }
    
    free(type);
    
    // Save current WiFi mode
    wifi_mode_t old_mode;
    esp_wifi_get_mode(&old_mode);
    
    // DEFAULT: normal scan (returns { networks: [...] })
    wifi_scan_config_t scan_conf = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 120,
        .scan_time.active.max = 120,
    };
    
    uint16_t count = 0;
    if (esp_wifi_scan_start(&scan_conf, true) == ESP_OK) {
        esp_wifi_scan_get_ap_num(&count);
        wifi_ap_record_t *records = malloc(count * sizeof(wifi_ap_record_t));
        if (records && esp_wifi_scan_get_ap_records(&count, records) == ESP_OK) {
            cJSON *root = cJSON_CreateObject();
            cJSON *nets = cJSON_AddArrayToObject(root, "networks");
            for (int i = 0; i < count; i++) {
                cJSON *n = cJSON_CreateObject();
                cJSON_AddStringToObject(n, "ssid", (char*)records[i].ssid);
                char bssid_str[18];
                snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    records[i].bssid[0], records[i].bssid[1], records[i].bssid[2],
                    records[i].bssid[3], records[i].bssid[4], records[i].bssid[5]);
                cJSON_AddStringToObject(n, "bssid", bssid_str);
                cJSON_AddNumberToObject(n, "channel", records[i].primary);
                cJSON_AddNumberToObject(n, "rssi", records[i].rssi);
                cJSON_AddBoolToObject(n, "is_5ghz", false);
                cJSON_AddItemToArray(nets, n);
            }
            free(records);
            cJSON_AddNumberToObject(root, "count", count);
            return send_json(req, root);
        }
        free(records);
    }
    
    return send_error(req, "Scan failed");
}

// ==================== DEAUTH START ====================
static esp_err_t api_deauth_start_handler(httpd_req_t *req) {
    size_t len = req->content_len;
    if (len <= 0) return send_error(req, "No data");
    
    char *buf = malloc(len + 1);
    if (!buf) return send_error(req, "Memory error");
    httpd_req_recv(req, buf, len);
    buf[len] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) return send_error(req, "Invalid JSON");
    
    cJSON *targets = cJSON_GetObjectItem(root, "targets");
    if (!cJSON_IsArray(targets)) {
        cJSON_Delete(root);
        return send_error(req, "No targets array");
    }
    
    int count = cJSON_GetArraySize(targets);
    deauth_target_t *deauth_targets = calloc(count, sizeof(deauth_target_t));
    int valid = 0;
    
    cJSON *t;
    cJSON_ArrayForEach(t, targets) {
        cJSON *bssid = cJSON_GetObjectItem(t, "bssid");
        cJSON *channel = cJSON_GetObjectItem(t, "channel");
        cJSON *is_5ghz = cJSON_GetObjectItem(t, "is_5ghz");
        
        if (bssid && cJSON_IsString(bssid)) {
            sscanf(bssid->valuestring, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                &deauth_targets[valid].bssid[0], &deauth_targets[valid].bssid[1],
                &deauth_targets[valid].bssid[2], &deauth_targets[valid].bssid[3],
                &deauth_targets[valid].bssid[4], &deauth_targets[valid].bssid[5]);
            deauth_targets[valid].channel = channel ? channel->valueint : 1;
            deauth_targets[valid].is_5ghz = is_5ghz ? cJSON_IsTrue(is_5ghz) : false;
            valid++;
        }
    }
    
    cJSON_Delete(root);
    
    uint8_t client_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    deauth_start(deauth_targets, valid, client_mac);
    free(deauth_targets);
    
    char msg[64];
    snprintf(msg, sizeof(msg), "Deauth started: %d targets", valid);
    return send_status(req, msg);
}

static esp_err_t api_deauth_stop_handler(httpd_req_t *req) {
    deauth_stop();
    return send_status(req, "Deauth stopped");
}

// ==================== EVILTWIN START (UPDATED with phishing_page) ====================
static esp_err_t api_eviltwin_start_handler(httpd_req_t *req) {
    size_t len = req->content_len;
    if (len <= 0) return send_error(req, "No data");
    
    char *buf = malloc(len + 1);
    if (!buf) return send_error(req, "Memory error");
    httpd_req_recv(req, buf, len);
    buf[len] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) return send_error(req, "Invalid JSON");
    
    cJSON *ssid = cJSON_GetObjectItem(root, "ssid");
    cJSON *bssid_json = cJSON_GetObjectItem(root, "bssid");
    cJSON *channel = cJSON_GetObjectItem(root, "channel");
    cJSON *is_5ghz = cJSON_GetObjectItem(root, "is_5ghz");
    cJSON *phishing_page = cJSON_GetObjectItem(root, "phishing_page");
    
    if (!ssid || !cJSON_IsString(ssid)) {
        cJSON_Delete(root);
        return send_error(req, "SSID required");
    }
    
    const char *target_ssid = ssid->valuestring;
    uint8_t target_bssid[6] = {0};
    uint8_t channel_val = channel ? channel->valueint : 6;
    bool is5 = is_5ghz ? cJSON_IsTrue(is_5ghz) : false;
    const char *phish = phishing_page && cJSON_IsString(phishing_page) ? phishing_page->valuestring : NULL;
    
    if (bssid_json && cJSON_IsString(bssid_json)) {
        sscanf(bssid_json->valuestring, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
               &target_bssid[0], &target_bssid[1], &target_bssid[2],
               &target_bssid[3], &target_bssid[4], &target_bssid[5]);
    }
    
    cJSON_Delete(root);
    
    // ✅ UPDATED: Pass phishing_page as 6th parameter
    eviltwin_start(target_ssid, target_ssid, target_bssid, channel_val, is5, phish);
    
    char msg[128];
    if (phish) {
        snprintf(msg, sizeof(msg), "EvilTwin started on '%s' with DevilTwin page: '%s' [%s]", 
                 target_ssid, phish, is5 ? "5GHz" : "2.4GHz");
    } else {
        snprintf(msg, sizeof(msg), "EvilTwin started on '%s' [%s]", 
                 target_ssid, is5 ? "5GHz" : "2.4GHz");
    }
    return send_status(req, msg);
}

static esp_err_t api_eviltwin_stop_handler(httpd_req_t *req) {
    eviltwin_stop();
    return send_status(req, "EvilTwin stopped");
}

// ==================== DEVILTWIN CAPTIVE PORTAL PAGE SERVER ====================
static esp_err_t serve_deviltwin_page_handler(httpd_req_t *req) {
    if (!g_current_phishing_page[0]) {
        // No active phishing page — return default or 404
        httpd_resp_set_type(req, "text/html");
        const char *default_page = "<html><body><h2>EvilTwin Captive Portal</h2><p>No phishing page configured.</p></body></html>";
        httpd_resp_sendstr(req, default_page);
        return ESP_OK;
    }
    
    char path[96];
    snprintf(path, sizeof(path), "%s/%s", SPIFFS_BASE_PATH, g_current_phishing_page);
    
    FILE *f = fopen(path, "r");
    if (!f) {
        ESP_LOGW(TAG, "DevilTwin page not found: %s", path);
        httpd_resp_set_type(req, "text/html");
        const char *err_page = "<html><body><h2>404</h2><p>Phishing page not found in SPIFFS.</p></body></html>";
        httpd_resp_sendstr(req, err_page);
        return ESP_OK;
    }
    
    httpd_resp_set_type(req, "text/html");
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *content = malloc(size + 1);
    if (!content) {
        fclose(f);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory error");
        return ESP_FAIL;
    }
    
    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);
    
    httpd_resp_send(req, content, size);
    free(content);
    
    ESP_LOGI(TAG, "📄 Served DevilTwin page: %s (%ld bytes)", g_current_phishing_page, size);
    return ESP_OK;
}

// ==================== FISHING_WEB PAGE SERVER (Beacon Spam) ====================
static esp_err_t serve_fishing_page_handler(httpd_req_t *req) {
    const char *query = strchr(req->uri, '?');
    char *page = get_query_param(query, "page");
    
    if (!page) {
        httpd_resp_set_type(req, "text/html");
        const char *err_page = "<html><body><h2>Error</h2><p>No fishing page specified.</p></body></html>";
        httpd_resp_sendstr(req, err_page);
        return ESP_OK;
    }
    
    char path[96];
    snprintf(path, sizeof(path), "%s/%s", SPIFFS_BASE_PATH, page);
    
    FILE *f = fopen(path, "r");
    if (!f) {
        ESP_LOGW(TAG, "Fishing page not found: %s", path);
        free(page);
        httpd_resp_set_type(req, "text/html");
        const char *err_page = "<html><body><h2>404</h2><p>Fishing page not found.</p></body></html>";
        httpd_resp_sendstr(req, err_page);
        return ESP_OK;
    }
    
    httpd_resp_set_type(req, "text/html");
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *content = malloc(size + 1);
    if (!content) {
        fclose(f);
        free(page);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory error");
        return ESP_FAIL;
    }
    
    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);
    
    httpd_resp_send(req, content, size);
    free(content);
    
    ESP_LOGI(TAG, "📄 Served Fishing_Web page: %s (%ld bytes)", page, size);
    free(page);
    return ESP_OK;
}

// ==================== BEACON START ====================
static esp_err_t api_beacon_start_handler(httpd_req_t *req) {
    size_t len = req->content_len;
    if (len <= 0) return send_error(req, "No data");
    
    char *buf = malloc(len + 1);
    if (!buf) return send_error(req, "Memory error");
    httpd_req_recv(req, buf, len);
    buf[len] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) return send_error(req, "Invalid JSON");
    
    cJSON *ssids_json = cJSON_GetObjectItem(root, "ssids");
    cJSON *quantities_json = cJSON_GetObjectItem(root, "quantities");
    cJSON *fishing_json = cJSON_GetObjectItem(root, "fishing_pages");
    
    if (!cJSON_IsArray(ssids_json)) {
        cJSON_Delete(root);
        return send_error(req, "SSIDs array required");
    }
    
    int count = cJSON_GetArraySize(ssids_json);
    if (count > 50) count = 50;
    
    const char **ssids = calloc(count, sizeof(char*));
    int *quantities = calloc(count, sizeof(int));
    const char **fishing = calloc(count, sizeof(char*));
    
    for (int i = 0; i < count; i++) {
        cJSON *s = cJSON_GetArrayItem(ssids_json, i);
        ssids[i] = s && cJSON_IsString(s) ? strdup(s->valuestring) : strdup("Unknown");
        
        if (quantities_json && cJSON_IsArray(quantities_json)) {
            cJSON *q = cJSON_GetArrayItem(quantities_json, i);
            quantities[i] = q && cJSON_IsNumber(q) ? q->valueint : 1;
        } else {
            quantities[i] = 1;
        }
        
        if (fishing_json && cJSON_IsArray(fishing_json)) {
            cJSON *f = cJSON_GetArrayItem(fishing_json, i);
            fishing[i] = f && cJSON_IsString(f) ? strdup(f->valuestring) : NULL;
        } else {
            fishing[i] = NULL;
        }
    }
    
    cJSON_Delete(root);
    
    beacon_spam_start(ssids, quantities, fishing, count);
    
    for (int i = 0; i < count; i++) {
        free((void*)ssids[i]);
        if (fishing[i]) free((void*)fishing[i]);
    }
    free(ssids);
    free(quantities);
    free(fishing);
    
    char msg[64];
    snprintf(msg, sizeof(msg), "Beacon spam: %d SSIDs", count);
    return send_status(req, msg);
}

static esp_err_t api_beacon_stop_handler(httpd_req_t *req) {
    beacon_spam_stop();
    return send_status(req, "Beacon spam stopped");
}

// ==================== JAMMER ====================
static esp_err_t api_jammer_wifi_handler(httpd_req_t *req) {
    jammer_wifi_start();
    return send_status(req, "WiFi Jammer started");
}

static esp_err_t api_jammer_bt_handler(httpd_req_t *req) {
    jammer_bt_start();
    return send_status(req, "BT Jammer started");
}

static esp_err_t api_jammer_stop_handler(httpd_req_t *req) {
    jammer_stop();
    return send_status(req, "Jammer stopped");
}

// ==================== WIFI DUCK ====================
static esp_err_t api_ducky_inject_handler(httpd_req_t *req) {
    size_t len = req->content_len;
    if (len <= 0) return send_error(req, "No script data");
    
    char *script = malloc(len + 1);
    if (!script) return send_error(req, "Memory error");
    httpd_req_recv(req, script, len);
    script[len] = '\0';
    
    cJSON *json = cJSON_Parse(script);
    const char *payload = script;
    if (json) {
        cJSON *s = cJSON_GetObjectItem(json, "script");
        if (s && cJSON_IsString(s)) payload = s->valuestring;
    }
    
    int result = ducky_inject(payload);
    
    if (json) cJSON_Delete(json);
    else free(script);
    
    if (result == 0) {
        return send_status(req, "Ducky script injected");
    } else {
        return send_error(req, "Injection failed");
    }
}

static esp_err_t api_ducky_stop_handler(httpd_req_t *req) {
    ducky_stop();
    return send_status(req, "Ducky injection stopped");
}

// ==================== PMKID ====================
static esp_err_t api_pmkid_list_handler(httpd_req_t *req) {
    char *json = pmkid_capture_export_json();
    if (!json) return send_error(req, "Failed to export PMKID data");
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    free(json);
    return ESP_OK;
}

static esp_err_t api_pmkid_start_handler(httpd_req_t *req) {
    size_t len = req->content_len;
    char *buf = malloc(len + 1);
    httpd_req_recv(req, buf, len);
    buf[len] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    
    uint8_t channel = 1;
    bool is_5ghz = false;
    
    if (root) {
        cJSON *ch = cJSON_GetObjectItem(root, "channel");
        if (ch) channel = ch->valueint;
        cJSON *is5 = cJSON_GetObjectItem(root, "is_5ghz");
        if (is5) is_5ghz = cJSON_IsTrue(is5);
        cJSON_Delete(root);
    }
    
    pmkid_capture_start(channel, is_5ghz);
    return send_status(req, "PMKID capture started");
}

static esp_err_t api_pmkid_stop_handler(httpd_req_t *req) {
    pmkid_capture_stop();
    return send_status(req, "PMKID capture stopped");
}

static esp_err_t api_pmkid_clear_handler(httpd_req_t *req) {
    pmkid_capture_clear();
    return send_status(req, "PMKID captures cleared");
}

static esp_err_t api_pmkid_auto_handler(httpd_req_t *req) {
    pmkid_capture_auto_scan();
    return send_status(req, "Auto PMKID scan started (all channels)");
}

// ==================== CHAIN ====================
static esp_err_t api_chain_start_handler(httpd_req_t *req) {
    attack_chain_start();
    return send_status(req, "Attack chain started");
}

static esp_err_t api_chain_stop_handler(httpd_req_t *req) {
    attack_chain_stop();
    return send_status(req, "Attack chain stopped");
}

static esp_err_t api_chain_status_handler(httpd_req_t *req) {
    attack_chain_status_t *status = attack_chain_get_status();
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "state", 
        status->state == ATTACK_CHAIN_IDLE ? "idle" :
        status->state == ATTACK_CHAIN_SCANNING ? "scanning" :
        status->state == ATTACK_CHAIN_DEAUTHING ? "deauthing" :
        status->state == ATTACK_CHAIN_CAPTURING ? "capturing" :
        status->state == ATTACK_CHAIN_COMPLETE ? "complete" : "failed");
    cJSON_AddStringToObject(root, "target_ssid", status->target_ssid);
    cJSON_AddNumberToObject(root, "deauth_count", status->deauth_count);
    cJSON_AddNumberToObject(root, "packets_captured", status->packets_captured);
    cJSON_AddBoolToObject(root, "pmkid_found", status->pmkid_found);
    if (status->pmkid_found) {
        cJSON_AddStringToObject(root, "last_pmkid", status->last_pmkid);
    }
    
    return send_json(req, root);
}

// ==================== TEMPLATES ====================
static esp_err_t api_templates_list_handler(httpd_req_t *req) {
    char *json = attack_templates_list_json();
    if (!json) return send_error(req, "Failed to list templates");
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    free(json);
    return ESP_OK;
}

static esp_err_t api_templates_deploy_handler(httpd_req_t *req) {
    size_t len = req->content_len;
    char *buf = malloc(len + 1);
    httpd_req_recv(req, buf, len);
    buf[len] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    
    if (!root) return send_error(req, "Invalid JSON");
    
    cJSON *id = cJSON_GetObjectItem(root, "template_id");
    if (!id) { cJSON_Delete(root); return send_error(req, "No template_id"); }
    
    esp_err_t err = attack_apply_template((attack_template_t)id->valueint);
    cJSON_Delete(root);
    
    if (err == ESP_OK) {
        return send_status(req, "Template deployed");
    }
    return send_error(req, "Failed to deploy template");
}

// ==================== FILES ====================
static esp_err_t api_files_list_handler(httpd_req_t *req) {
    DIR *dir = opendir(SPIFFS_BASE_PATH);
    if (!dir) {
        return send_error(req, "Failed to open SPIFFS");
    }
    
    cJSON *root = cJSON_CreateObject();
    cJSON *files = cJSON_AddArrayToObject(root, "files");
    cJSON *sizes = cJSON_AddObjectToObject(root, "sizes");
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            cJSON_AddItemToArray(files, cJSON_CreateString(entry->d_name));
            
            char path[320];  // /spiffs/ + max filename (255) + null
            snprintf(path, sizeof(path), "%s/%s", SPIFFS_BASE_PATH, entry->d_name);
            struct stat st;
            if (stat(path, &st) == 0) {
                char size_str[16];
                snprintf(size_str, sizeof(size_str), "%d", (int)st.st_size);
                cJSON_AddStringToObject(sizes, entry->d_name, size_str);
            }
        }
    }
    closedir(dir);
    
    return send_json(req, root);
}

static esp_err_t api_files_read_handler(httpd_req_t *req) {
    const char *query = strchr(req->uri, '?');
    char *filename = get_query_param(query, "file");
    
    if (!filename) return send_error(req, "No file specified");
    
    char path[64];
    snprintf(path, sizeof(path), "%s/%s", SPIFFS_BASE_PATH, filename);
    
    FILE *f = fopen(path, "r");
    if (!f) {
        free(filename);
        return send_error(req, "File not found");
    }
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *content = malloc(fsize + 1);
    if (!content) {
        fclose(f);
        free(filename);
        return send_error(req, "Memory error");
    }
    fread(content, 1, fsize, f);
    content[fsize] = '\0';
    fclose(f);
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "filename", filename);
    cJSON_AddStringToObject(root, "content", content);
    
    free(content);
    free(filename);
    return send_json(req, root);
}

static esp_err_t api_files_upload_handler(httpd_req_t *req) {
    const char *query = strchr(req->uri, '?');
    char *filename = get_query_param(query, "path");
    
    if (!filename) {
        int clen = req->content_len;
        if (clen <= 0) return send_error(req, "No data");
        filename = strdup("uploaded_file");
    }
    
    for (char *p = filename; *p; p++) {
        if (*p == '/' || *p == '\\') *p = '_';
    }
    
    char path[64];
    snprintf(path, sizeof(path), "%s/%s", SPIFFS_BASE_PATH, filename);
    
    if (req->content_len > MAX_FILE_SIZE) {
        free(filename);
        return send_error(req, "File too large (max 512KB)");
    }
    
    FILE *f = fopen(path, "wb");
    if (!f) {
        free(filename);
        return send_error(req, "Failed to create file");
    }
    
    char buf[MAX_SCRATCH_BUF];
    int received;
    int remaining = req->content_len;
    
    while (remaining > 0) {
        int to_read = remaining < MAX_SCRATCH_BUF ? remaining : MAX_SCRATCH_BUF;
        if ((received = httpd_req_recv(req, buf, to_read)) <= 0) {
            if (received == HTTPD_SOCK_ERR_TIMEOUT) continue;
            fclose(f);
            unlink(path);
            free(filename);
            return send_error(req, "Receive failed");
        }
        fwrite(buf, 1, received, f);
        remaining -= received;
    }
    
    fclose(f);
    ESP_LOGI(TAG, "File uploaded: %s (%d bytes)", filename, req->content_len);
    
    char msg[128];
    snprintf(msg, sizeof(msg), "Uploaded: %s (%d bytes)", filename, req->content_len);
    free(filename);
    return send_status(req, msg);
}

static esp_err_t api_files_delete_handler(httpd_req_t *req) {
    size_t len = req->content_len;
    char *buf = malloc(len + 1);
    if (!buf) return send_error(req, "Memory error");
    httpd_req_recv(req, buf, len);
    buf[len] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    
    if (!root) return send_error(req, "Invalid JSON");
    
    cJSON *file = cJSON_GetObjectItem(root, "file");
    if (!file || !cJSON_IsString(file)) {
        cJSON_Delete(root);
        return send_error(req, "No file specified");
    }
    
    char path[64];
    snprintf(path, sizeof(path), "%s/%s", SPIFFS_BASE_PATH, file->valuestring);
    
    struct stat st;
    if (stat(path, &st) != 0) {
        cJSON_Delete(root);
        return send_error(req, "File not found");
    }
    
    unlink(path);
    cJSON_Delete(root);
    
    return send_status(req, "File deleted");
}

// ==================== CAPTURED DATA ====================
extern int captured_data_get_count(void);
extern const char* captured_data_get(int index, char *ssid_buf, char *pass_buf, char *time_buf);

static esp_err_t api_captured_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateObject();
    cJSON *data = cJSON_AddArrayToObject(root, "data");
    
    int count = captured_data_get_count();
    char ssid[64], pass[64], time_str[32];
    
    for (int i = 0; i < count; i++) {
        if (captured_data_get(i, ssid, pass, time_str)) {
            cJSON *entry = cJSON_CreateObject();
            cJSON_AddStringToObject(entry, "ssid", ssid);
            cJSON_AddStringToObject(entry, "password", pass);
            cJSON_AddStringToObject(entry, "time", time_str);
            cJSON_AddItemToArray(data, entry);
        }
    }
    
    cJSON_AddNumberToObject(root, "count", count);
    return send_json(req, root);
}

static esp_err_t api_captured_clear_handler(httpd_req_t *req) {
    captured_data_clear();
    return send_status(req, "Captured data cleared");
}

// ==================== CONSOLE ====================
static esp_err_t api_console_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "ok");
    cJSON_AddStringToObject(root, "message", "Console monitoring active");
    return send_json(req, root);
}

// ==================== STATIC FILE SERVER ====================
static esp_err_t index_html_get_handler(httpd_req_t *req) {
    char path[576];
    const char *uri = req->uri;
    
    if (strcmp(uri, "/") == 0 || strcmp(uri, "/dashboard.html") == 0) {
        snprintf(path, sizeof(path), "%s/dashboard.html", SPIFFS_BASE_PATH);
    } else {
        snprintf(path, sizeof(path), "%s%s", SPIFFS_BASE_PATH, uri);
    }
    
    FILE *f = fopen(path, "r");
    if (!f) {
        if (strcmp(uri, "/") == 0 || strcmp(uri, "/dashboard.html") == 0) {
            httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "dashboard.html not found in SPIFFS. Upload it first.");
            return ESP_FAIL;
        }
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
        return ESP_FAIL;
    }
    
    const char *ext = strrchr(uri, '.');
    const char *content_type = "text/html";
    if (ext) {
        if (strcmp(ext, ".css") == 0) content_type = "text/css";
        else if (strcmp(ext, ".js") == 0) content_type = "application/javascript";
        else if (strcmp(ext, ".png") == 0) content_type = "image/png";
        else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) content_type = "image/jpeg";
        else if (strcmp(ext, ".ico") == 0) content_type = "image/x-icon";
        else if (strcmp(ext, ".json") == 0) content_type = "application/json";
        else if (strcmp(ext, ".txt") == 0) content_type = "text/plain";
    }
    
    httpd_resp_set_type(req, content_type);
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *content = malloc(fsize);
    if (!content) {
        fclose(f);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory error");
        return ESP_FAIL;
    }
    
    fread(content, 1, fsize, f);
    fclose(f);
    
    httpd_resp_send(req, content, fsize);
    free(content);
    
    return ESP_OK;
}

// ==================== REGISTER ALL HANDLERS ====================
void webserver_start(void) {
    if (server) {
        ESP_LOGW(TAG, "Server already running");
        return;
    }
    
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.lru_purge_enable = true;
    config.max_uri_handlers = 35;  // Increased for new handlers
    config.uri_match_fn = httpd_uri_match_wildcard;
    
    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return;
    }
    
    ESP_LOGI(TAG, "HTTP server started on port 80");
    register_all_api_handlers(server);
    ESP_LOGI(TAG, "All API handlers registered");
}

void register_all_api_handlers(httpd_handle_t server) {

    // ===== STATUS =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/status", .method = HTTP_GET,
        .handler = api_status_handler, .user_ctx = NULL
    });

    // ===== SCAN =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/scan", .method = HTTP_GET,
        .handler = api_scan_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/scan/all", .method = HTTP_GET,
        .handler = api_scan_all_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/scan/stop", .method = HTTP_GET,
        .handler = api_scan_stop_handler, .user_ctx = NULL
    });

    // ===== DEAUTH =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/deauth/start", .method = HTTP_POST,
        .handler = api_deauth_start_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/deauth/stop", .method = HTTP_GET,
        .handler = api_deauth_stop_handler, .user_ctx = NULL
    });
    
    // ===== EVIL TWIN =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/eviltwin/start", .method = HTTP_POST,
        .handler = api_eviltwin_start_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/eviltwin/stop", .method = HTTP_GET,
        .handler = api_eviltwin_stop_handler, .user_ctx = NULL
    });
    
    // ===== DEVILTWIN CAPTIVE PORTAL PAGE =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/eviltwin/portal", .method = HTTP_GET,
        .handler = serve_deviltwin_page_handler, .user_ctx = NULL
    });
    
    // ===== FISHING_WEB PAGE (Beacon Spam) =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/fishing/page", .method = HTTP_GET,
        .handler = serve_fishing_page_handler, .user_ctx = NULL
    });
    
    // ===== BEACON SPAM =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/beacon/start", .method = HTTP_POST,
        .handler = api_beacon_start_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/beacon/stop", .method = HTTP_GET,
        .handler = api_beacon_stop_handler, .user_ctx = NULL
    });
    
    // ===== JAMMER =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/jammer/wifi", .method = HTTP_GET,
        .handler = api_jammer_wifi_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/jammer/bt", .method = HTTP_GET,
        .handler = api_jammer_bt_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/jammer/stop", .method = HTTP_GET,
        .handler = api_jammer_stop_handler, .user_ctx = NULL
    });
    
    // ===== WIFI DUCK =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/ducky/inject", .method = HTTP_POST,
        .handler = api_ducky_inject_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/ducky/stop", .method = HTTP_GET,
        .handler = api_ducky_stop_handler, .user_ctx = NULL
    });

    // ===== PMKID =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/pmkid/list", .method = HTTP_GET,
        .handler = api_pmkid_list_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/pmkid/start", .method = HTTP_POST,
        .handler = api_pmkid_start_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/pmkid/stop", .method = HTTP_GET,
        .handler = api_pmkid_stop_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/pmkid/clear", .method = HTTP_GET,
        .handler = api_pmkid_clear_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/pmkid/auto", .method = HTTP_GET,
        .handler = api_pmkid_auto_handler, .user_ctx = NULL
    });

    // ===== ATTACK CHAIN =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/chain/start", .method = HTTP_GET,
        .handler = api_chain_start_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/chain/stop", .method = HTTP_GET,
        .handler = api_chain_stop_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/chain/status", .method = HTTP_GET,
        .handler = api_chain_status_handler, .user_ctx = NULL
    });

    // ===== TEMPLATES =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/templates/list", .method = HTTP_GET,
        .handler = api_templates_list_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/templates/deploy", .method = HTTP_POST,
        .handler = api_templates_deploy_handler, .user_ctx = NULL
    });
    
    // ===== FILES =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/files/list", .method = HTTP_GET,
        .handler = api_files_list_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/files/read", .method = HTTP_GET,
        .handler = api_files_read_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/files/upload", .method = HTTP_POST,
        .handler = api_files_upload_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/files/delete", .method = HTTP_POST,
        .handler = api_files_delete_handler, .user_ctx = NULL
    });
    
    // ===== CAPTURED =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/captured", .method = HTTP_GET,
        .handler = api_captured_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/captured/clear", .method = HTTP_GET,
        .handler = api_captured_clear_handler, .user_ctx = NULL
    });
    
    // ===== CONSOLE =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/api/console", .method = HTTP_GET,
        .handler = api_console_handler, .user_ctx = NULL
    });
    
    // ===== STATIC FILES =====
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/", .method = HTTP_GET,
        .handler = index_html_get_handler, .user_ctx = NULL
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/*", .method = HTTP_GET,
        .handler = index_html_get_handler, .user_ctx = NULL
    });
}    

void webserver_stop(void) {
    if (server) {
        httpd_stop(server);
        server = NULL;
        ESP_LOGI(TAG, "HTTP server stopped");
    }
}
