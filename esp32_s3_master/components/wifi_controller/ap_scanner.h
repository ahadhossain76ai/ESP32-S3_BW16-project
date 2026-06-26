#ifndef AP_SCANNER_H
#define AP_SCANNER_H

#include "esp_wifi_types.h"
#include <stdbool.h>

int ap_scanner_get_count(void);
wifi_ap_record_t* ap_scanner_get_results(void);
bool ap_scanner_is_scan_complete(void);
void ap_scanner_set_results(wifi_ap_record_t *recs, int n);
void ap_scanner_reset(void);

#endif