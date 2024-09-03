// use curl or wget (GET or HEAD) if any command other than get or head - code 501 
// if client tries to access forbidden site through proxy - code 403
#include <stdbool.h>  
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <netdb.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_FORBIDDEN_SITES 1000
#define MAX_HOSTNAME_LEN 256

char forbidden_sites[MAX_FORBIDDEN_SITES][MAX_HOSTNAME_LEN];
int forbidden_sites_count = 0;
char access_log_filename[256];
SSL_CTX *ctx; // Global variable for SSL context


typedef struct ThreadArgs {
    int socket_fd;
    struct sockaddr_in client_addr;
} ThreadArgs;

typedef struct ServerConnectionInfo {
    int socket_fd;   // Socket descriptor
    char method[10]; // HTTP method (GET, HEAD, etc.)
    char url[512];   // Full URL
    char hostname[256]; // Extracted hostname from URL
    char ip[INET6_ADDRSTRLEN]; // IP address in string format (supports IPv6)
} ServerConnectionInfo;





void parse_url(const char *url, char *hostname) {
    // Example URL: http://www.example.com/path
    const char *host_start = strstr(url, "://");
    if (!host_start) {
        host_start = url; // No scheme in URL, start at the beginning
    } else {
        host_start += 3; // Skip past "://"
    }

    const char *host_end = strchr(host_start, '/');
    if (!host_end) {
        host_end = url + strlen(url); // No path, URL ends at the end of the hostname
    }

    ptrdiff_t hostname_len = host_end - host_start;
    strncpy(hostname, host_start, hostname_len);
    hostname[hostname_len] = '\0'; // Null-terminate the hostname
}





ServerConnectionInfo* connect_to_server(const char *url) {
    ServerConnectionInfo *info = malloc(sizeof(ServerConnectionInfo));
    if (!info) {
        perror("Failed to allocate info");
        return NULL;
    }

    // Extract hostname from URL
    parse_url(url, info->hostname);

    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Both IPv4 and IPv6 are acceptable
    hints.ai_socktype = SOCK_STREAM; // TCP socket

    int status;
    if ((status = getaddrinfo(info->hostname, "http", &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        free(info);
        return NULL;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        info->socket_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (info->socket_fd == -1) continue;

        if (connect(info->socket_fd, p->ai_addr, p->ai_addrlen) != -1) {
            // Successfully connected
            break;
        }

        close(info->socket_fd);
    }

    if (p == NULL) {
        fprintf(stderr, "Failed to connect\n");
        freeaddrinfo(res);
        free(info);
        return NULL;
    }

    // Convert IP address to string
    char ipstr[INET6_ADDRSTRLEN];
    void *addr;
    if (p->ai_family == AF_INET) { // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        addr = &(ipv4->sin_addr);
    } else { // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
        addr = &(ipv6->sin6_addr);
    }
    inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
    strncpy(info->ip, ipstr, INET6_ADDRSTRLEN);

    freeaddrinfo(res); // Free the linked list

    return info;
}





// Log each request and its outcome to a access.log file
void log_request(const char* client_ip, const char* request_line, int status_code, size_t response_size) {
    FILE *log_file = fopen("access.log", "a"); // Open the log file in append mode
    if (log_file == NULL) {
        perror("Error opening log file");
        return;
    }

    // Get the current time
    time_t now = time(NULL);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    fprintf(log_file, "%s %s \"%s\" %d %zu\n", time_str, client_ip, request_line, status_code, response_size);

    fclose(log_file);
}



// Function to load forbidden sites from a file
bool load_forbidden_sites(const char* filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening forbidden sites file");
        return false;
    }

    char line[MAX_HOSTNAME_LEN];
    forbidden_sites_count = 0;
    while (fgets(line, sizeof(line), file) && forbidden_sites_count < MAX_FORBIDDEN_SITES) {
        line[strcspn(line, "\n")] = 0; // Remove newline character
        strncpy(forbidden_sites[forbidden_sites_count++], line, MAX_HOSTNAME_LEN);
    }

    fclose(file);
    return true;
}




// Handle error scenarios and log them
void send_error_response(int client_socket, const char *status_code, const char *message, const char *client_ip) {
    char response[1024];
    sprintf(response, "HTTP/1.1 %s %s\r\n\r\n", status_code, message);
    send(client_socket, response, strlen(response), 0);
    log_request(client_ip, message, atoi(status_code), strlen(response));
}





void print_ssl_errors() {
    ERR_print_errors_fp(stderr);
}




void log_ssl_error() {
    long err;
    while ((err = ERR_get_error()) != 0) {
        char *str_error = ERR_error_string(err, 0);
        if (str_error) {
            fprintf(stderr, "SSL error: %s\n", str_error);
        }
    }
}




void *handle_client_request(void *args) {
    ThreadArgs *thread_args = (ThreadArgs *)args;
    int client_socket = thread_args->socket_fd;
    SSL *ssl = NULL;

    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) {
        perror("Read error");
        close(client_socket);
        free(thread_args);
        return NULL;
    }

    // Parse the request
    char method[10], url[512], protocol[10];
    if (sscanf(buffer, "%9s %511s %9s", method, url, protocol) != 3) {
        // Malformed request
        send_error_response(client_socket, "400", "Bad Request", inet_ntoa(thread_args->client_addr.sin_addr));
        close(client_socket);
        free(thread_args);
        return NULL;
    }

    // Check for GET or HEAD method
    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
        send_error_response(client_socket, "501", "Not Implemented", inet_ntoa(thread_args->client_addr.sin_addr));
        close(client_socket);
        free(thread_args);
        return NULL;
    }

    bool is_https = strncmp(url, "https://", 8) == 0;
    ServerConnectionInfo *dest_server_info = connect_to_server(url);
    if (dest_server_info == NULL) {
        // Connection to server failed
        send_error_response(client_socket, "502", "Bad Gateway", inet_ntoa(thread_args->client_addr.sin_addr));
        close(client_socket);
        free(thread_args);
        return NULL;
    }

    // Setup SSL for HTTPS
    if (is_https) {
        ssl = SSL_new(ctx);
        if (!ssl) {
            log_ssl_error();
            send_error_response(client_socket, "500", "Internal Server Error", inet_ntoa(thread_args->client_addr.sin_addr));
            close(dest_server_info->socket_fd);
            free(dest_server_info);
            close(client_socket);
            free(thread_args);
            return NULL;
        }

        SSL_set_fd(ssl, dest_server_info->socket_fd);
        if (SSL_connect(ssl) <= 0) {
            log_ssl_error();
            send_error_response(client_socket, "500", "Internal Server Error", inet_ntoa(thread_args->client_addr.sin_addr));
            SSL_free(ssl);
            close(dest_server_info->socket_fd);
            free(dest_server_info);
            close(client_socket);
            free(thread_args);
            return NULL;
        }
    }

    // Forward request to server
    if (is_https) {
        SSL_write(ssl, buffer, strlen(buffer));
    } else {
        send(dest_server_info->socket_fd, buffer, strlen(buffer), 0);
    }

    // Receive response from server and send to client
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        ssize_t response_length = is_https ? SSL_read(ssl, buffer, sizeof(buffer) - 1) : read(dest_server_info->socket_fd, buffer, sizeof(buffer) - 1);

        if (response_length <= 0) {
            break;
        }

        send(client_socket, buffer, response_length, 0);
    }

    // Cleanup
    if (is_https) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    close(dest_server_info->socket_fd);
    free(dest_server_info);
    close(client_socket);
    free(thread_args);
    return NULL;
}

int main(int argc, char *argv[]) {
    // Check if the correct number of arguments is provided
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <port number> <forbidden file name> <access log name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    // Initialize SSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
  
    const SSL_METHOD *method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);

    if (!ctx) {
        // Handle error: SSL context creation failed
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        fprintf(stderr, "Unable to set default verify paths\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } 

    // Convert port number from string to int and validate
    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port number.\n");
        exit(EXIT_FAILURE);
    }

    // Load the forbidden sites
    strncpy(access_log_filename, argv[3], sizeof(access_log_filename));
    if (!load_forbidden_sites(argv[2])) { // argv[2] is the forbidden file name
        fprintf(stderr, "Failed to load forbidden sites.\n");
        exit(EXIT_FAILURE);
    }

    printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    //printf("Available ciphers: %s\n", SSL_get_cipher_list(ctx, 0));
    
    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Socket creation and setup
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    printf("Listening on port %d...\n", port);

    // Accept loop
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addrlen = sizeof(client_addr);
        int new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            continue;
        }

        ThreadArgs *thread_args = malloc(sizeof(ThreadArgs));
        if (!thread_args) {
            perror("Failed to allocate thread_args");
            close(new_socket);
            continue;
        }
        thread_args->socket_fd = new_socket;
        thread_args->client_addr = client_addr;

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client_request, (void *)thread_args) != 0) {
            perror("Failed to create thread");
            close(new_socket);
            free(thread_args);
        } else {
            pthread_detach(thread_id);
        }
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    ERR_free_strings();
    EVP_cleanup();
    return 0;
}
