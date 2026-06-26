#ifndef WEBSERVER_H
#define WEBSERVER_H

#include "esp_http_server.h"

void webserver_start(void);
void webserver_stop(void);
void register_all_api_handlers(httpd_handle_t server);

/**
 * @brief Set active DevilTwin phishing page for captive portal
 * @param path Path to HTML file in SPIFFS (e.g. "DevilTwin/EvilTwin_tp_link.html")
 *        Pass NULL to clear
 */
void set_active_phishing_page(const char *path);

#endif // WEBSERVER_H
