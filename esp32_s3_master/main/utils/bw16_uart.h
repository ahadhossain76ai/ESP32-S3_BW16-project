#ifndef BW16_UART_H
#define BW16_UART_H

#include <stdint.h>
#include <stdbool.h>
#include "driver/uart.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define BW16_UART_NUM       UART_NUM_2
#define BW16_UART_TX_PIN    GPIO_NUM_17
#define BW16_UART_RX_PIN    GPIO_NUM_18
#define BW16_UART_BAUD      115200
#define BW16_UART_BUF_SIZE  1024

typedef struct {
    bool connected;
    bool deauth_active;
    bool jammer_active;
    uint32_t frames_sent;
    uint32_t network_count;
    char last_response[256];
} bw16_status_t;

// Initialization
void bw16_uart_init(void);

// Send commands
void bw16_send_command(const char *cmd);
void bw16_send_formatted(const char *fmt, ...);

// Response handling
char* bw16_read_response(TickType_t timeout);
void bw16_flush_responses(void);

// Status
bool bw16_is_connected(void);
bw16_status_t* bw16_get_status(void);

// 5GHz WiFi operations
void bw16_scan_5ghz(void);
void bw16_deauth_start(const char *targets_json);
void bw16_deauth_stop(void);
void bw16_eviltwin_start(const char *params_json);
void bw16_eviltwin_stop(void);
void bw16_jammer_start(void);
void bw16_jammer_stop(void);
void bw16_stop_all(void);

// Repeater operations
int bw16_repeater_start(const char *ssid, const char *password);
void bw16_repeater_stop(void);
void bw16_repeater_scan(void);

#endif
