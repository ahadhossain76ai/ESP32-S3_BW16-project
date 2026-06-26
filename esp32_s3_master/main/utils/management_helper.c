#include "management_helper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_spiffs.h"

static const char *TAG = "mgmt_helper";

char* load_html_from_spiffs(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open %s", path);
        return NULL;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size <= 0) { fclose(f); return NULL; }
    
    char *buf = (char*)malloc(size + 1);
    if (!buf) { fclose(f); return NULL; }
    
    fread(buf, 1, size, f);
    buf[size] = '\0';
    fclose(f);
    
    return buf;
}
