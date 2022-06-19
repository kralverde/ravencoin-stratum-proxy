#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include "base64.h"
#include "cJSON.h"

// Ravencoin max block size is 2MB * 2 for hex
#define MAX_READ 1024 * 1024 * 3 * 2

static const char *GETBLOCKTEMPLATE_REQ_A = "POST / HTTP/1.0\r\nAuthorization: Basic ";
static const char *GETBLOCKTEMPLATE_REQ_B = "\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"getblocktemplate\",\"params\":[]}";    

typedef struct template_state
{
    char *node_authentication;
    char *getblocktemplate_post;
    unsigned char address_h160[0x14];

    int height;
    
    // The following are directly used in apis and are stored accordingly
    char *bits;
    char *target;
    char *header_hash;

    uint32_t version;
    uint8_t *previous_block_hash;
    // A null terminated array of transactions in hex
    char **external_transactions;
    uint8_t *seed_hash;
    uint8_t *new_header;
    uint8_t *coinbase_tx;
    uint8_t *coinbase_txid;

    int request_id;

} template_state;

static void update_state(template_state *state, char *node_ip, int node_port)
{
    char buff[MAX_READ];
    char *json_ptr;
    char *json_str;
    int b_read, to_node_socket;
    struct sockaddr_in to_node_addr;
    cJSON *json;
    cJSON *json_response;
    cJSON *json_child;

    // HTTP Requests must be reopened each time.
    to_node_socket = socket(AF_INET, SOCK_STREAM, 0);
    if ( to_node_socket == -1)
    {
        printf("Failed to create a socket to the node\n");
        exit(0);
    }

    bzero(&to_node_addr, sizeof(to_node_addr));

    to_node_addr.sin_family = AF_INET;
    to_node_addr.sin_addr.s_addr = inet_addr(node_ip);
    to_node_addr.sin_port = htons(node_port);
    if (connect(to_node_socket, (struct sockaddr *)&to_node_addr, sizeof(to_node_addr)) != 0)
    {
        printf("Failed to connect to the node: %s\n", strerror(errno));
        exit(0);
    }

    write(to_node_socket, state->getblocktemplate_post, strlen(state->getblocktemplate_post));
    b_read = read(to_node_socket, buff, sizeof(buff));
    close(to_node_socket);
    
    // TODO: Better validation
    if ( buff[MAX_READ-1] != 0 )
    {
        printf("Response too large!\n");
        exit(0);
    }

    if ( !strstr(buff, "200 OK") )
    {
        printf("Invalid response:\n%s\n", buff);
        exit(0);
    }
    
    if ( !(json_ptr = strstr(buff, "\r\n\r\n")) )
    {
        printf("Malformed response:\n%s\n", buff);
        exit(0);
    }

    json = cJSON_Parse(json_ptr);
    json_response = cJSON_GetObjectItem(json, "result");
    if (!json_response)
    {
        printf("Invalid JSON:\n%s\n", cJSON_Print(json));
        exit(0);
    }

    json_child = cJSON_GetObjectItem(json_response, "height");
    if ( !cJSON_IsNumber(json_child))
    {
        printf("Invalid JSON (1):\n%s\n", cJSON_Print(json));
        exit(0);
    }
    state->height = (int)cJSON_GetNumberValue(json_child);

    json_child = cJSON_GetObjectItem(json_response, "bits");
    if ( !cJSON_IsString(json_child) )
    {
        printf("Invalid JSON (2):\n%s\n", cJSON_Print(json));
        exit(0);
    }
    if ( state->bits )
    {
        free(state->bits);
    }
    state->bits = (char *) malloc((sizeof(char)) * (strlen(cJSON_GetStringValue(json_child)) + 1));
    if ( !state->bits )
    {
        printf("Failed to allocate memory for bits\n");
        exit(0);
    }
    strcpy(state->bits, cJSON_GetStringValue(json_child));

    printf("%s\n", cJSON_Print(json));
    cJSON_Delete(json);
}

static void begin(int proxy_port, char *node_ip, char *node_authentication, int node_port, int listen_externally, int is_testnet)
{
    template_state state;
    bzero(&state, sizeof(state));
    
    state.node_authentication = node_authentication;
    state.getblocktemplate_post = (char *) malloc (sizeof(char) * (1 + strlen(GETBLOCKTEMPLATE_REQ_A) + strlen(GETBLOCKTEMPLATE_REQ_B) + strlen(state.node_authentication)));
    if (!state.getblocktemplate_post)
    {
        printf("Failed to allocate memory for the getblocktemplate request\n");
        exit(0);
    }
    bzero(state.getblocktemplate_post, sizeof(state.getblocktemplate_post));
    strcpy(state.getblocktemplate_post, GETBLOCKTEMPLATE_REQ_A);
    strcpy(&state.getblocktemplate_post[strlen(GETBLOCKTEMPLATE_REQ_A)], state.node_authentication);
    strcpy(&state.getblocktemplate_post[strlen(GETBLOCKTEMPLATE_REQ_A)+strlen(state.node_authentication)], GETBLOCKTEMPLATE_REQ_B);

    // Attempt to populate the state here.
    update_state(&state, node_ip, node_port);
}

int main(int argc, char **argv)
{
    int proxy_port, node_port, should_listen_externally, should_testnet, node_authentication_len;
    char *node_authentication;
    char *node_authentication_raw;

    if (argc < 7)
    {
        printf("arguments must be: proxy_port, node_ip, node_username, node_password, node_port, listen_externally, (testnet - optional)\n");
        exit(0);
    }

    proxy_port = atoi(argv[1]);
    if ( !proxy_port )
    {
        printf("Invalid proxy port.\n");
        exit(0);
    }

    node_port = atoi(argv[5]);
    if ( !node_port )
    {
        printf("Invalid node port.\n");
        exit(0);
    }

    should_listen_externally = atoi(argv[6]);
    if ( !should_listen_externally )
    {
        if (argv[6][0] == 't' || argv[6][0] == 'T')
        {
            should_listen_externally = 1;
        }
    }

    should_testnet = 0;
    if ( argc > 7 )
    {
        should_testnet = atoi(argv[7]);
        if ( !should_testnet )
        {
            if (argv[7][0] == 't' || argv[7][0] == 'T')
            {
                should_testnet = 1;
            }
        }
    }
    
    node_authentication_raw = (char *) malloc((sizeof(char)) * (2 + strlen(argv[3]) + strlen(argv[4])));
    if ( !node_authentication_raw )
    {
        printf("Failed to allocate memory for the raw authentication string\n");
        exit(0);
    }
    
    strcpy(node_authentication_raw, argv[3]);
    node_authentication_raw[strlen(argv[3])] = ':';
    strcpy(&node_authentication_raw[strlen(argv[3]) + 1], argv[4]);
    
    node_authentication_len = b64e_size(strlen(node_authentication_raw)) + 1;
    node_authentication = (char *) malloc((sizeof(char)) * node_authentication_len);

    if ( !node_authentication )
    {
        printf("Failed to allocate memory for the authentication string\n");
        exit(0);
    }

    b64_encode(node_authentication_raw, strlen(node_authentication_raw), node_authentication);
    free(node_authentication_raw);
    node_authentication[node_authentication_len-1] = 0;
    begin(proxy_port, argv[2], node_authentication, node_port, should_listen_externally, should_testnet);

    return 0;
}