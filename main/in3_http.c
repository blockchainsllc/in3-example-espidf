/*******************************************************************************
 * This file is part of the Incubed project.
 * Sources: https://github.com/slockit/in3-c
 * 
 * Copyright (C) 2018-2019 slock.it GmbH, Blockchains LLC
 * 
 * 
 * COMMERCIAL LICENSE USAGE
 * 
 * Licensees holding a valid commercial license may use this file in accordance 
 * with the commercial license agreement provided with the Software or, alternatively, 
 * in accordance with the terms contained in a written agreement between you and 
 * slock.it GmbH/Blockchains LLC. For licensing terms and conditions or further 
 * information please contact slock.it at in3@slock.it.
 * 	
 * Alternatively, this file may be used under the AGPL license as follows:
 *    
 * AGPL LICENSE USAGE
 * 
 * This program is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Affero General Public License as published by the Free Software 
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
 * PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
 * [Permissions of this strong copyleft license are conditioned on making available 
 * complete source code of licensed works and modifications, which include larger 
 * works using a licensed work, under the same license. Copyright and license notices 
 * must be preserved. Contributors provide an express grant of patent rights.]
 * You should have received a copy of the GNU Affero General Public License along 
 * with this program. If not, see <https://www.gnu.org/licenses/>.
 *******************************************************************************/

#include <string.h>
#include <fcntl.h>
#include "esp_http_server.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_vfs.h"
#include "cJSON.h"
#include "esp_http_client.h"
#include <esp_log.h>
#include "freertos/task.h"
#include "util/debug.h"
#include "util/stringbuilder.h"
#include "util/log.h"

#include "client/client.h"

#include <in3/eth_full.h> // the full ethereum verifier containing the EVM
#include <in3/eth_api.h> // wrapper for easier use


static const char *REST_TAG = "esp-rest";
static sb_t *http_in3_buffer = NULL;
static in3_t *c;
static const char *TAG = "IN3";

/* http event handler  */
esp_err_t s_http_event_handler(esp_http_client_event_t *evt)
{
    switch (evt->event_id)
    {
    case HTTP_EVENT_ERROR:
        ESP_LOGI(TAG, "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        if (http_in3_buffer != NULL)
            sb_free(http_in3_buffer);
        http_in3_buffer = sb_new("");
        ESP_LOGI(TAG, "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGI(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        // fill the http response buffer with the http data chunks
        sb_add_range(http_in3_buffer, (char *)evt->data, 0, evt->data_len);
        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGI(TAG, "HTTP_EVENT_ON_FINISH");
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
        break;
    }
    return ESP_OK;
}
/* http client request to in3 servers*/
void send_request(char *url, char *payload)
{

    // setup post request and send with to in3 url and payload
    esp_http_client_handle_t client;
    esp_http_client_config_t configc = {
        .url = url,
        .transport_type = HTTP_TRANSPORT_OVER_TCP,
        .event_handler = s_http_event_handler,
    };
    client = esp_http_client_init(&configc);
    const char *post_data = payload;
    ESP_LOGI(TAG, "REQUEST %s %s\n", post_data, url);
    //esp_http_client_set_url(client, url);
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Accept", "application/json");
    esp_http_client_set_header(client, "charsets", "utf-8");
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK)
    {
        esp_http_client_cleanup(client);
    }
    else
    {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
    }
}


/* Freertos task for evm call requests */
void in3_task_evm(void *pvParameters)
{
    address_t contract;
    // setup lock access contract address to be excuted with eth_call
    hex2byte_arr("0x36643F8D17FE745a69A2Fd22188921Fade60a98B", -1, contract, 20);
    //ask for the access to the lock
    json_ctx_t *response = eth_call_fn(c, contract, BLKNUM_LATEST(), "hasAccess():bool");
    if (!response){
        dbg_log("Could not get the response: %s", eth_last_error());
        return;
    }
    // convert the response to a uint32_t,
    uint8_t access = d_int(response->result);
    dbg_log("Access granted? : %d %s %d\n", access);

    // clean up resources
    free_json(response);
    vTaskDelete(NULL);
}

/* Freertos task for get block number requests */    
void in3_task_blk_number(void *pvParameters)
{
    eth_block_t *block = eth_getBlockByNumber(c, BLKNUM(6970454), true);
    if (!block)
        dbg_log("Could not find the Block: %s\n", eth_last_error());
    else
    {
        ESP_LOGI(REST_TAG, "Number of verified transactions in block: %d\n", block->tx_count);
        free(block);
    }
    vTaskDelete(NULL);
}

/* GET endpoint /api/access rest handler for in3 request */
static esp_err_t exec_get_handler(httpd_req_t *req)
{
    // trigger freertos task to process in3 calls and cache the result in 
    xTaskCreate(in3_task_evm, "uTask", 28048, NULL, 7, NULL);
    httpd_resp_set_type(req, "application/json");
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "response", "request received successfully, please use the retrieve button after 2 minutes");
    const char *slock_ret = cJSON_Print(root);
    httpd_resp_sendstr(req, slock_ret);
    free((void *)slock_ret);
    cJSON_Delete(root);
    return ESP_OK;
}

/* GET endpoint /api/retrieve rest handler for in3 requests */
static esp_err_t retrieve_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "response", http_in3_buffer->data);
    const char *slock_ret = cJSON_Print(root);
    httpd_resp_sendstr(req, slock_ret);
    free((void *)slock_ret);
    cJSON_Delete(root);
    return ESP_OK;
}
/* Perform in3 requests for http transport */
static in3_ret_t transport_esphttp(in3_request_t* req)
{

    for (int i = 0; i < req->urls_len; i++){
        send_request( req->urls[i], req->payload);
        sb_add_range(&req->results[i].result, http_in3_buffer->data, 0, http_in3_buffer->len);
        //ESP_LOGI(TAG, "RESPONSE data = %s len =%d ", http_in3_buffer->data, http_in3_buffer->len);
    }
    return 0;
}

/* Setup and init in3 */
void init_in3(void)
{
    // init in3
    c = in3_new();
    in3_register_eth_full();
    c->transport = transport_esphttp; // use esp_idf_http client to handle the requests
    c->requestCount = 1;           // number of requests to sendp
    c->includeCode = 1;
    //c->use_binary = 1;
    c->proof = PROOF_FULL;
    c->max_attempts = 1;
    c->chainId = 0x5; // use kovan
    in3_log_set_level(LOG_TRACE);
}
/* setup and init local http rest server */
esp_err_t start_rest_server(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;

    ESP_LOGI(REST_TAG, "Starting HTTP Server");
    if (httpd_start(&server, &config) == ESP_OK)
    {
        // Set URI handlers
        ESP_LOGI(REST_TAG, "Registering URI handlers");
        /* URI handler for fetching system info */
        httpd_uri_t exec_uri = {
            .uri = "/api/access",
            .method = HTTP_GET,
            .handler = exec_get_handler,
            .user_ctx = NULL};
        httpd_register_uri_handler(server, &exec_uri);
        httpd_uri_t retrieve_uri = {
            .uri = "/api/retrieve",
            .method = HTTP_GET,
            .handler = retrieve_get_handler,
            .user_ctx = NULL};
        httpd_register_uri_handler(server, &retrieve_uri);
        init_in3();
    }
    return ESP_OK;
}
