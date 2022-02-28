#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include <stdbool.h>

#include "WiFi_Creds.h"


void connect_wifi(bool *isConnected);