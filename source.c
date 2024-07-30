#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>

#define NUM_THREADS 5
#define MAX_MSG_LEN 2048
#define MAX_MSG_BUF_LEN (MAX_MSG_LEN + 100)
#define MAX_EVENTS 10
#define KEY 0x1a0a

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} LogLevel;

char *ip_address, *port, *veri_code;
int epoll_fd = 0;
int nfds = 0;
FILE *log_file = NULL;
FILE *access_log_file = NULL;

void log_message(LogLevel level, const char *format, ...);
void log_access(const char *client_ip, const char *request);

void handle_request(int conn_fd);
void send_response(int conn_fd, int status_code, const char *filename);
void send_file(int client_socket, const char *filename);
void search_response(int connfd, int status_code, const char *filename, char *keyword);
void search_file(int client_socket, const char *filename, char *keyword);


int sigint_flag = 0;
void sigint_handler(int sig) {
    log_message(LOG_INFO, "[srv] SIGINT is coming!\n");
    sigint_flag = 1;
}

void send_file(int client_socket, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        send(client_socket, "HTTP/1.1 404 Not Found\r\n\r\n", 27, 0);
        return;
    }

    char buffer[MAX_MSG_BUF_LEN];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, MAX_MSG_BUF_LEN, file)) > 0) {
        send(client_socket, buffer, bytes_read, 0);
    }

    fclose(file);
}



void handle_request(int conn_fd) {
    char request[MAX_MSG_BUF_LEN];
    int n = read(conn_fd, request, sizeof(request));
    
    char method[10], path[50], http_version[10];
    sscanf(request, "%9s %49s %9s", method, path, http_version);

	char real_path[60];
    sprintf(real_path, "./blog%s", path);
	
    log_access("127.0.0.1", request);
    

    if (strstr(real_path, "search"))
    {   
        if(strncmp(method, "GET", 3) == 0 && !strstr(real_path, ".html")){
            char *temp;
            char key1[10], key2[20];
            strtok(real_path, "=");
            temp = strtok(NULL, "=");
            strncpy(key1, temp, 4);
            key1[4] = '\0';
            strcat(key1, ".txt");
            strcpy(key2, strtok(NULL, "="));
            printf("%s\n", key1);
            printf("%s\n", key2);
            if (access(key1, F_OK) != -1)
            {   
                search_response(conn_fd, 200, key1, key2);
            }else
            {
                search_response(conn_fd, 404, NULL, NULL);
            }
        } else if(strncmp(method, "POST", 4) == 0){
            strtok(request, "\n");
            char *temp;
            while (request != NULL)
            {
                temp = strtok(NULL, "\n");
                if (strstr(temp, "key1=")) {
				    break; 
				}
               
            }
            
            char *temp1;
            char key1[10], key2[20];
            strtok(temp, "=");
            temp1 = strtok(NULL, "=");
            strncpy(key1, temp1, 4);
            key1[4] = '\0';
            strcat(key1, ".txt");
            strncpy(key2, strtok(NULL, "="), 4);
           	key2[4] = '\0'; 
           	
            
            printf("%s\n", key1);
            printf("%s\n", key2);
            
            if (access(key1, F_OK) != -1)
            {   
                search_response(conn_fd, 200, key1, key2);
            }else
            {
                search_response(conn_fd, 404, NULL, NULL);
            }
        }else{
            if (access(real_path, F_OK) != -1) {
                send_response(conn_fd, 200, real_path);
            } else {
                send_response(conn_fd, 404, NULL);
            }
        }
    }else
    {
        if(strncmp(method, "GET", 3) != 0){
            send_response(conn_fd, 501, NULL);
        } else{
            if (access(real_path, F_OK) != -1) {
                send_response(conn_fd, 200, real_path);
            } else {
                send_response(conn_fd, 404, NULL);
            }
        }
    }
}



void search_response(int conn_fd, int status_code, const char *filename, char *keyword){
    const char *status_message = (status_code == 200) ? "OK" : "Not Found";
    const char *content_type = "text/plain";
    char response[1024];
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        send(conn_fd, "HTTP/1.1 404 Not Found\r\n\r\n", 27, 0);
        return;
    }
	
    char buffer[MAX_MSG_BUF_LEN];
    char *temp;
    size_t bytes_read;
    while (fgets(temp, MAX_MSG_BUF_LEN, file) != NULL) 
    {
        if (strncmp(keyword, "male", 4) == 0)
        {
            if (strstr(temp, keyword) && !strstr(temp, "female"))
            {
                strcat(buffer, temp);
            }
        }else{
            if (strstr(temp, keyword))
            {
                strcat(buffer, temp);
            }
        }
        
    }

    fclose(file);


    struct stat stat_buf;
    if (status_code == 200 && filename && stat(filename, &stat_buf) == 0) {
        snprintf(response, sizeof(response),
                 "HTTP/1.1 %d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %ld\r\n"
                 "Connection: keep-alive\r\n"
                 "\r\n",
                 status_code, status_message, content_type, sizeof(buffer));
    } else {
        snprintf(response, sizeof(response),
                 "HTTP/1.1 %d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: 3\r\n"
                 "Connection: keep-alive\r\n"
                 "\r\n"
                 "%d",
                 status_code, status_message, content_type, status_code);
    }

    int n = send(conn_fd, response, strlen(response), 0);
    if (n < 0) {
        perror("send");
    }

    if (status_code == 200 && filename) {
        n = send(conn_fd, buffer, strlen(buffer), 0);
        printf("%s\n", buffer);
        if (n < 0) {
            perror("send");
        }
    }
}

void send_response(int conn_fd, int status_code, const char *filename) {
    const char *status_message = (status_code == 200) ? "OK" : "Not Found";
    const char *content_type = "text/plain";
    char response[1024];

    if (status_code == 200 && filename) {
        if (strstr(filename, ".html")) {
            content_type = "text/html; charset=UTF-8";
        } else if (strstr(filename, ".css")) {
            content_type = "text/css";
        } else if (strstr(filename, ".js")) {
            content_type = "application/javascript";
        } else if (strstr(filename, ".jpg")) {
            content_type = "image/jpeg";
        } else if (strstr(filename, ".gif")) {
            content_type = "image/gif";
        } else if (strstr(filename, ".ico")) {
            content_type = "image/x-icon";
        }
    }
    
    struct stat stat_buf;
    if (status_code == 200 && filename && stat(filename, &stat_buf) == 0) {
        snprintf(response, sizeof(response),
                 "HTTP/1.1 %d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %ld\r\n"
                 "Connection: keep-alive\r\n"
                 "\r\n",
                 status_code, status_message, content_type, (long)stat_buf.st_size);
    } else {
        snprintf(response, sizeof(response),
                 "HTTP/1.1 %d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: 3\r\n"
                 "Connection: keep-alive\r\n"
                 "\r\n"
                 "%d",
                 status_code, status_message, content_type, status_code);
    }

    int n = send(conn_fd, response, strlen(response), 0);
    if (n < 0) {
        perror("send");
    }

    if (status_code == 200 && filename) {
        send_file(conn_fd, filename);
    }
}

void log_message(LogLevel level, const char *format, ...) {
    const char *level_str[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
    char buffer[1024];
    va_list args;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), " [%s] ", level_str[level]);

    va_start(args, format);
    vsnprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), format, args);
    va_end(args);

    fputs(buffer, log_file);
    fputs("\n", log_file);
    fflush(log_file);
}

void log_access(const char *client_ip, const char *request) {
    char buffer[1024];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), " - %s - \"%s\"\n", client_ip, request);

    fputs(buffer, access_log_file);
    fflush(access_log_file);
}

int main(int argc, char *argv[]) {
    ip_address = argv[1];
    port = argv[2];
	
	printf("%s\n", ip_address);
	printf("%s\n", port);
	
    log_file = fopen("server.log", "a");
    access_log_file = fopen("access.log", "a");

    struct sigaction act;
    act.sa_flags = 0;
    act.sa_handler = sigint_handler;
    sigemptyset(&act.sa_mask);
    sigaction(SIGINT, &act, NULL);

    int listen_fd = socket(PF_INET, SOCK_STREAM, 0);

    struct sockaddr_in srv_address;
    memset(&srv_address, 0, sizeof(srv_address));
    srv_address.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip_address, &srv_address.sin_addr.s_addr) < 0) {
        log_message(LOG_ERROR, "inet_pton error");
        exit(EXIT_FAILURE);
    }
    srv_address.sin_port = htons(atoi(port));
    if (bind(listen_fd, (struct sockaddr *)&srv_address, sizeof(srv_address)) < 0) {
        log_message(LOG_ERROR, "bind error");
        exit(EXIT_FAILURE);
    }

    listen(listen_fd, 5);
    log_message(LOG_INFO, "[srv] server[%s:%s] is initializing!", ip_address, port);

    int conn_fd;
    struct sockaddr_in cli_address;
    socklen_t cli_address_len = sizeof(cli_address);
    log_message(LOG_INFO, "[srv] Server has initialized!");

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        log_message(LOG_ERROR, "epoll_create1");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        log_message(LOG_ERROR, "epoll_ctl");
        exit(EXIT_FAILURE);
    }

    while (!sigint_flag) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == listen_fd) {
                if ((conn_fd = accept(listen_fd, (struct sockaddr *)&cli_address, &cli_address_len)) < 0) {
                    if (errno ==EINTR)
                        continue;
                    else {
                        log_message(LOG_ERROR, "accept error");
                        continue;
                    }
                }
                log_message(LOG_INFO, "[srv] client[%s:%d] is accepted!", inet_ntoa(cli_address.sin_addr), ntohs(cli_address.sin_port));

                ev.events = EPOLLIN | EPOLLHUP;
                ev.data.fd = conn_fd;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) < 0) {
                    log_message(LOG_ERROR, "epoll_ctl");
                    continue;
                }

                log_message(LOG_DEBUG, "New client connected, total clients: %d", ++nfds);

            } else if (events[i].events & EPOLLIN) {
                handle_request(events[i].data.fd);
                close(events[i].data.fd);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                nfds--;
            }
        }
    }

    fclose(log_file);
    fclose(access_log_file);
    close(epoll_fd);
    if (close(listen_fd) < 0)
        log_message(LOG_ERROR, "close error");
    log_message(LOG_INFO, "[srv] listen_fd is closed!");
    log_message(LOG_INFO, "[srv] server is to return!");
    return 0;
}
