/*
 * bw16_uart.c — Enhanced UART communication with BW16 RTL8720DN
 * JSON-based command protocol for 5GHz operations
 */

#include "bw16_uart.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

static const char *TAG = "bw16_uart";
static bw16_status_t g_bw16_status = {0};
static char rx_buffer[BW16_UART_BUF_SIZE];
static int rx_index = 0;
static QueueHandle_t response_queue = NULL;
static TaskHandle_t uart_rx_task_handle = NULL;

// ==================== UART RX TASK ====================
static void uart_rx_task(void *pv) {
    uint8_t data;
    char line_buffer[BW16_UART_BUF_SIZE];
    int line_idx = 0;
    
    while (1) {
        while (uart_read_bytes(BW16_UART_NUM, &data, 1, pdMS_TO_TICKS(10)) > 0) {
            if (data == '\n' || line_idx >= BW16_UART_BUF_SIZE - 1) {
                line_buffer[line_idx] = '\0';
                
                if (line_idx > 0) {
                    ESP_LOGD(TAG, "RX<-BW16: %s", line_buffer);
                    
                    // Update status based on response
                    if (strstr(line_buffer, "PONG") || strstr(line_buffer, "BW16_READY")) {
                        g_bw16_status.connected = true;
                    }
                    
                    // Store for API consumption
                    strncpy(g_bw16_status.last_response, line_buffer, 
                            sizeof(g_bw16_status.last_response) - 1);
                    
                    // Send to response queue if anyone is waiting
                    if (response_queue) {
                        char *resp = strdup(line_buffer);
                        if (resp) {
                            xQueueSend(response_queue, &resp, pdMS_TO_TICKS(10));
                        }
                    }
                }
                
                line_idx = 0;
            } else {
                line_buffer[line_idx++] = (char)data;
            }
        }
        
        // Update status flags from responses
        if (strstr(g_bw16_status.last_response, "DEAUTH_STARTED") || 
            strstr(g_bw16_status.last_response, "Deauth started")) {
            g_bw16_status.deauth_active = true;
        }
        if (strstr(g_bw16_status.last_response, "JAMMER_STARTED") ||
            strstr(g_bw16_status.last_response, "Jammer started")) {
            g_bw16_status.jammer_active = true;
        }
        if (strstr(g_bw16_status.last_response, "stopped") ||
            strstr(g_bw16_status.last_response, "completed")) {
            g_bw16_status.deauth_active = false;
            g_bw16_status.jammer_active = false;
        }
        
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}

// ==================== INIT ====================
void bw16_uart_init(void) {
    uart_config_t uart_config = {
        .baud_rate = BW16_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    
    ESP_ERROR_CHECK(uart_param_config(BW16_UART_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(BW16_UART_NUM, BW16_UART_TX_PIN, BW16_UART_RX_PIN, 
                                  UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    ESP_ERROR_CHECK(uart_driver_install(BW16_UART_NUM, BW16_UART_BUF_SIZE * 2, 
                                          BW16_UART_BUF_SIZE * 2, 0, NULL, 0));
    
    // Create response queue
    response_queue = xQueueCreate(10, sizeof(char*));
    
    // Start UART receive task
    xTaskCreatePinnedToCore(uart_rx_task, "bw16_rx", 4096, NULL, 5, &uart_rx_task_handle, 0);
    
    g_bw16_status.connected = false;
    g_bw16_status.deauth_active = false;
    g_bw16_status.jammer_active = false;
    g_bw16_status.frames_sent = 0;
    g_bw16_status.network_count = 0;
    g_bw16_status.last_response[0] = '\0';
    
    ESP_LOGI(TAG, "UART2 initialized: TX=GPIO17, RX=GPIO18 @115200 baud");
}

// ==================== SEND COMMANDS ====================
void bw16_send_command(const char *cmd) {
    if (!cmd) return;
    
    size_t len = strlen(cmd);
    int written = uart_write_bytes(BW16_UART_NUM, cmd, len);
    
    if (written > 0) {
        ESP_LOGD(TAG, "TX->BW16: %s", cmd);
        g_bw16_status.frames_sent++;
    } else {
        ESP_LOGE(TAG, "Failed to send command to BW16");
    }
}

void bw16_send_formatted(const char *fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    // Ensure newline at end
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] != '\n') {
        strncat(buf, "\n", sizeof(buf) - len - 1);
    }
    
    bw16_send_command(buf);
}

// ==================== RESPONSE HANDLING ====================
char* bw16_read_response(TickType_t timeout) {
    if (!response_queue) return NULL;
    
    char *resp = NULL;
    if (xQueueReceive(response_queue, &resp, timeout) == pdTRUE) {
        return resp;
    }
    return NULL;
}

void bw16_flush_responses(void) {
    char *resp;
    while (xQueueReceive(response_queue, &resp, 0) == pdTRUE) {
        free(resp);
    }
}

// ==================== STATUS ====================
bool bw16_is_connected(void) { 
    return g_bw16_status.connected; 
}

bw16_status_t* bw16_get_status(void) {
    return &g_bw16_status;
}

// ==================== 5GHz OPERATIONS ====================
void bw16_scan_5ghz(void) {
    bw16_flush_responses();
    bw16_send_command("SCAN_5GHZ\n");
}

void bw16_deauth_start(const char *targets_json) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "DEAUTH:START %s\n", targets_json);
    bw16_send_command(cmd);
}

void bw16_deauth_stop(void) {
    bw16_send_command("DEAUTH:STOP\n");
}

void bw16_eviltwin_start(const char *params_json) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "EVILTWIN:START %s\n", params_json);
    bw16_send_command(cmd);
}

void bw16_eviltwin_stop(void) {
    bw16_send_command("EVILTWIN:STOP\n");
}

void bw16_jammer_start(void) {
    bw16_send_command("JAMMER:START\n");
}

void bw16_jammer_stop(void) {
    bw16_send_command("JAMMER:STOP\n");
}

void bw16_stop_all(void) {
    bw16_send_command("STOP\n");
}

// ==================== REPEATER OPERATIONS ====================
int bw16_repeater_start(const char *ssid, const char *password) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "REPEATER:CONNECT {\"ssid\":\"%s\",\"password\":\"%s\"}\n", 
             ssid, password ? password : "");
    bw16_send_command(cmd);
    
    // Wait for response
    char *resp = bw16_read_response(pdMS_TO_TICKS(5000));
    if (resp) {
        int ret = (strstr(resp, "\"status\":\"ok\"") != NULL) ? 0 : -1;
        free(resp);
        return ret;
    }
    return -1;
}

void bw16_repeater_stop(void) {
    bw16_send_command("REPEATER:STOP\n");
}

void bw16_repeater_scan(void) {
    bw16_flush_responses();
    bw16_send_command("REPEATER:SCAN\n");
}
