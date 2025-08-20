/*
 * paping - A paping-like TCP/UDP/ICMP ping tool for Linux
 * 
 * Behavior:
 * - No port specified  -> ICMP mode (raw sockets), paping-styled output.
 * - -p/--port given    -> TCP mode by default, UDP if -u/--udp.
 * - Infinite by default; stop with Ctrl+C.
 *
 * Examples:
 *   paping 8.8.8.8
 *   paping 8.8.8.8 -p 443
 *   paping 8.8.8.8 -p 53 -u
 *
 * Compile with: gcc -o paping paping.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>

// ANSI color codes
#define GREEN "\033[92m"
#define RED   "\033[91m"
#define RESET "\033[0m"

// Global variables for signal handling
volatile sig_atomic_t running = 1;

// ICMP packet structure
struct icmp_packet {
    struct icmphdr icmp_hdr;
    char payload[64];
};

// Function prototypes
void signal_handler(int sig);
unsigned short checksum(unsigned short *addr, int len);
int icmp_ping(const char *host, int count, float interval, float timeout);
int tcp_udp_ping(const char *host, int port, int count, float interval, float timeout, int udp);
void print_usage(const char *progname);
double get_time_ms(void);

// Signal handler to gracefully exit
void signal_handler(int sig) {
    (void)sig;
    running = 0;
    printf("\n");
}

// Calculate ICMP checksum
unsigned short checksum(unsigned short *addr, int len) {
    int nleft = len;
    unsigned short *w = addr;
    unsigned short answer;
    int sum = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

// Get current time in milliseconds
double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

// ICMP ping implementation
int icmp_ping(const char *host, int count, float interval, float timeout) {
    struct sockaddr_in addr;
    struct icmp_packet packet;
    int sock, seq = 0, sent = 0, received = 0;
    char buffer[1024];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    struct timeval tv;
    fd_set readfds;
    
    // Resolve hostname
    struct hostent *he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "%sCannot resolve %s%s\n", RED, host, RESET);
        return 1;
    }
    
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    
    // Create raw socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        fprintf(stderr, "%sICMP requires root or CAP_NET_RAW (try sudo).%s\n", RED, RESET);
        return 1;
    }
    
    // Set timeout
    tv.tv_sec = (int)timeout;
    tv.tv_usec = (int)((timeout - (int)timeout) * 1000000);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    printf("PING %s (%s): %d data bytes\n", host, inet_ntoa(addr.sin_addr), (int)sizeof(packet.payload));
    
    while (running && (count == 0 || sent < count)) {
        // Prepare ICMP packet
        memset(&packet, 0, sizeof(packet));
        packet.icmp_hdr.type = 8; // ICMP_ECHOREQUEST
        packet.icmp_hdr.code = 0;
        packet.icmp_hdr.un.echo.id = getpid() & 0xFFFF;
        packet.icmp_hdr.un.echo.sequence = ++seq;
        
        // Add timestamp to payload
        double timestamp = get_time_ms();
        memcpy(packet.payload, &timestamp, sizeof(timestamp));
        
        // Calculate checksum
        packet.icmp_hdr.checksum = 0;
        packet.icmp_hdr.checksum = checksum((unsigned short *)&packet, sizeof(packet));
        
        // Send packet
        if (sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            fprintf(stderr, "%sFailed to send packet%s\n", RED, RESET);
            continue;
        }
        
        sent++;
        double start_time = get_time_ms();
        
        // Wait for reply
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        
        int select_result = select(sock + 1, &readfds, NULL, NULL, &tv);
        if (select_result > 0) {
            ssize_t recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &fromlen);
            if (recv_len > 0) {
                // Skip IP header (20 bytes)
                struct icmphdr *icmp = (struct icmphdr *)(buffer + 20);
                if (icmp->type == 0 && // ICMP_ECHOREPLY
                    icmp->un.echo.id == (getpid() & 0xFFFF) && 
                    icmp->un.echo.sequence == seq) {
                    
                    double end_time = get_time_ms();
                    double rtt = end_time - start_time;
                    received++;
                    
                    printf("Connected to %s%s%s: time=%s%.2fms%s protocol=%sICMP%s\n",
                           GREEN, inet_ntoa(addr.sin_addr), RESET,
                           GREEN, rtt, RESET,
                           GREEN, RESET);
                }
            }
        } else {
            printf("%sConnection timed out%s\n", RED, RESET);
        }
        
        // Sleep between pings
        if (running && (count == 0 || sent < count)) {
            usleep((unsigned int)(interval * 1000000));
        }
    }
    
    close(sock);
    
    if (sent > 0) {
        printf("\n--- %s ping statistics ---\n", host);
        printf("%d packets transmitted, %d received, %.1f%% packet loss\n",
               sent, received, ((float)(sent - received) / sent) * 100);
    }
    
    return 0;
}

// TCP/UDP ping implementation
int tcp_udp_ping(const char *host, int port, int count, float interval, float timeout, int udp) {
    struct sockaddr_in addr;
    int sock, sent = 0, received = 0;
    const char *proto = udp ? "UDP" : "TCP";
    
    // Resolve hostname
    struct hostent *he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "%sCannot resolve %s%s\n", RED, host, RESET);
        return 1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    printf("PING %s (%s): %s port %d\n", host, inet_ntoa(addr.sin_addr), proto, port);
    
    while (running && (count == 0 || sent < count)) {
        // Create socket
        sock = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
        if (sock < 0) {
            fprintf(stderr, "%sFailed to create socket%s\n", RED, RESET);
            continue;
        }
        
        // Set timeout
        struct timeval tv;
        tv.tv_sec = (int)timeout;
        tv.tv_usec = (int)((timeout - (int)timeout) * 1000000);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        sent++;
        double start_time = get_time_ms();
        
        int success = 0;
        if (udp) {
            // UDP: send empty packet
            if (sendto(sock, "", 0, 0, (struct sockaddr *)&addr, sizeof(addr)) >= 0) {
                char buffer[1024];
                struct sockaddr_in from;
                socklen_t fromlen = sizeof(from);
                
                if (recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &fromlen) >= 0) {
                    success = 1;
                }
            }
        } else {
            // TCP: connect
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                success = 1;
            }
        }
        
        close(sock);
        
        if (success) {
            double end_time = get_time_ms();
            double rtt = end_time - start_time;
            received++;
            
            printf("Connected to %s%s%s: time=%s%.2fms%s protocol=%s%s%s port=%s%d%s\n",
                   GREEN, inet_ntoa(addr.sin_addr), RESET,
                   GREEN, rtt, RESET,
                   GREEN, proto, RESET,
                   GREEN, port, RESET);
        } else {
            printf("%sConnection timed out%s\n", RED, RESET);
        }
        
        // Sleep between pings
        if (running && (count == 0 || sent < count)) {
            usleep((unsigned int)(interval * 1000000));
        }
    }
    
    if (sent > 0) {
        printf("\n--- %s %s ping statistics ---\n", host, proto);
        printf("%d packets transmitted, %d received, %.1f%% packet loss\n",
               sent, received, ((float)(sent - received) / sent) * 100);
    }
    
    return 0;
}

// Print usage information
void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS] HOST\n", progname);
    printf("\nOptions:\n");
    printf("  -p, --port PORT     Port number (enables TCP mode by default)\n");
    printf("  -u, --udp           Use UDP instead of TCP (when -p is given)\n");
    printf("  -c, --count COUNT   Number of probes (default: infinite)\n");
    printf("  -i, --interval SEC  Interval between probes in seconds (default: 1.0)\n");
    printf("  -t, --timeout SEC   Timeout in seconds (default: 3.0)\n");
    printf("  -h, --help          Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s 8.8.8.8\n", progname);
    printf("  %s 8.8.8.8 -p 443\n", progname);
    printf("  %s 8.8.8.8 -p 53 -u\n", progname);
}

int main(int argc, char *argv[]) {
    char *host = NULL;
    int port = -1;
    int udp = 0;
    int count = 0;
    float interval = 1.0;
    float timeout = 3.0;
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Parse command line arguments
    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"udp", no_argument, 0, 'u'},
        {"count", required_argument, 0, 'c'},
        {"interval", required_argument, 0, 'i'},
        {"timeout", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:uc:i:t:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                if (port <= 0 || port > 65535) {
                    fprintf(stderr, "%sInvalid port number: %s%s\n", RED, optarg, RESET);
                    return 1;
                }
                break;
            case 'u':
                udp = 1;
                break;
            case 'c':
                count = atoi(optarg);
                if (count < 0) {
                    fprintf(stderr, "%sInvalid count: %s%s\n", RED, optarg, RESET);
                    return 1;
                }
                break;
            case 'i':
                interval = atof(optarg);
                if (interval <= 0) {
                    fprintf(stderr, "%sInvalid interval: %s%s\n", RED, optarg, RESET);
                    return 1;
                }
                break;
            case 't':
                timeout = atof(optarg);
                if (timeout <= 0) {
                    fprintf(stderr, "%sInvalid timeout: %s%s\n", RED, optarg, RESET);
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Get hostname
    if (optind >= argc) {
        fprintf(stderr, "%sError: hostname required%s\n", RED, RESET);
        print_usage(argv[0]);
        return 1;
    }
    host = argv[optind];
    
    // Validate arguments
    if (udp && port == -1) {
        fprintf(stderr, "%sError: UDP mode requires port specification (-p)%s\n", RED, RESET);
        return 1;
    }
    
    // Run appropriate ping function
    if (port == -1) {
        return icmp_ping(host, count, interval, timeout);
    } else {
        return tcp_udp_ping(host, port, count, interval, timeout, udp);
    }
}
