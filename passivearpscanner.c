//cybersupervisor passive arp scanner
//written by Rob Rogers rob@legendaryitsolutions.ca
//feb 15 2024

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_ENTRIES 1024

typedef struct {
    char ip[INET_ADDRSTRLEN];
    char mac[18];
    char timestamp[64]; // Timestamp field
    time_t first_seen;
    time_t last_seen;
    int count;
    char organization[256];
    char dns_name[256]; // Added for DNS lookup
} arp_entry;

arp_entry arp_table[MAX_ENTRIES];
int arp_table_size = 0;
bool enable_dns_lookup = true;
bool enable_unix_time = false;
bool enable_summary = false; // Changed default to false
bool enable_summary_thread = true;
FILE* output_file = NULL;
char* oui_data = NULL;
char oui_file_location[1024] = "/usr/share/ieee-data/oui.txt";
pthread_mutex_t lock;

void cleanup_resources() {
    if (oui_data != NULL) {
        free(oui_data);
        oui_data = NULL;
    }
    if (output_file != stdout && output_file != NULL) {
        fclose(output_file);
    }
    pthread_mutex_destroy(&lock);
}

void atexit_handler() {
    cleanup_resources();
}

void mac_to_str(const unsigned char* mac, char* mac_str) {
    snprintf(mac_str, 18, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void sanitize_organization(char* org) {
    int len = strlen(org), start = 0, end = len - 1;
    while (start < len && isspace(org[start])) ++start;
    while (end > start && isspace(org[end])) --end;
    org[end + 1] = '\0'; // Null-terminate at the new end position

    // Shift the trimmed string to the beginning
    if (start > 0) {
        memmove(org, org + start, end - start + 1);
    }

    // Condense multiple spaces into one
    char *dst = org;
    for (char *src = org; *src != '\0'; ++src) {
        *dst++ = *src;
        if (isspace((unsigned char)*src)) {
            do ++src; while (isspace((unsigned char)*src));
            --src;
        }
    }
    *dst = '\0';
}

const char* lookup_oui(const unsigned char* mac) {
    if (oui_data == NULL) {
        fprintf(stderr, "OUI data not loaded\n");
        return "Unknown Organization";
    }

    char prefix[9];
    snprintf(prefix, sizeof(prefix), "%02X-%02X-%02X", mac[0], mac[1], mac[2]);

    char* line = oui_data;
    while ((line = strstr(line, prefix)) != NULL) {
        if (line == oui_data || *(line - 1) == '\n') {
            char* org_start = strchr(line, '\t');
            if (org_start != NULL) {
                org_start++;
                char* org_end = strchr(org_start, '\n');
                if (org_end != NULL) {
                    static char organization[256];
                    strncpy(organization, org_start, org_end - org_start);
                    organization[org_end - org_start] = '\0';
                    sanitize_organization(organization);
                    return organization;
                }
            }
        }
        line++;
    }

    return "Organization Not Found";
}

void load_oui_data() {
    FILE* file = fopen(oui_file_location, "r");
    if (!file) {
        perror("Error opening OUI file");
        exit(EXIT_FAILURE); // Ensure program exits if critical resources are unavailable
    }

    struct stat st;
    if (fstat(fileno(file), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size == 0) {
        fclose(file);
        fprintf(stderr, "Invalid OUI file\n");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    oui_data = (char*)malloc(file_size + 1);
    if (oui_data == NULL) {
        perror("Error allocating memory for OUI data");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    size_t bytes_read = fread(oui_data, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        perror("Error reading OUI data");
        free(oui_data);
        oui_data = NULL;
        fclose(file);
        exit(EXIT_FAILURE);
    } else {
        oui_data[file_size] = '\0';
    }

    fclose(file);
}

void perform_dns_lookup(const char* ip_addr, char* dns_name) {
    if (!enable_dns_lookup || ip_addr == NULL || dns_name == NULL) {
        strcpy(dns_name, "DNS lookup disabled or IP null");
        return;
    }
    struct hostent* he;
    struct in_addr ipv4addr;
    inet_pton(AF_INET, ip_addr, &ipv4addr);
    he = gethostbyaddr(&ipv4addr, sizeof(ipv4addr), AF_INET);
    if (he) {
        strncpy(dns_name, he->h_name, 255);
        dns_name[255] = '\0'; // Ensure null-termination
    } else {
        strcpy(dns_name, "Not found");
    }
}

bool update_arp_table(const char* src_ip, const unsigned char* src_mac, time_t now) {
    char mac_str[18];
    mac_to_str(src_mac, mac_str);
    char dns_name[256] = {0};

    perform_dns_lookup(src_ip, dns_name);

    pthread_mutex_lock(&lock);
    for (int i = 0; i < arp_table_size; i++) {
        if (strcmp(arp_table[i].ip, src_ip) == 0) {
            arp_table[i].last_seen = now;
            arp_table[i].count++;
            pthread_mutex_unlock(&lock);
            return false; // Duplicate found
        }
    }

    if (arp_table_size >= MAX_ENTRIES) {
        fprintf(stderr, "ARP table is full\n");
        pthread_mutex_unlock(&lock);
        return false;
    }

    strncpy(arp_table[arp_table_size].ip, src_ip, INET_ADDRSTRLEN);
    strncpy(arp_table[arp_table_size].mac, mac_str, 18);
    arp_table[arp_table_size].first_seen = now;
    arp_table[arp_table_size].last_seen = now;
    arp_table[arp_table_size].count = 1;
    const char* organization = lookup_oui(src_mac);
    strncpy(arp_table[arp_table_size].organization, organization, 255);
    strncpy(arp_table[arp_table_size].dns_name, dns_name, 255);
    arp_table_size++;
    pthread_mutex_unlock(&lock);
    return true; // New entry added
}

void* print_summary(void* arg) {
    while (enable_summary_thread) {
        sleep(30); // Wait for 30 seconds between summaries
        if (!enable_summary) {
            continue;
        }
        pthread_mutex_lock(&lock);
        for (int i = 0; i < arp_table_size; i++) {
            time_t first_seen_time = arp_table[i].first_seen;
            time_t last_seen_time = arp_table[i].last_seen;
            struct tm* first_seen_tm = localtime(&first_seen_time);
            struct tm* last_seen_tm = localtime(&last_seen_time);
            char first_seen_str[64], last_seen_str[64];
            if (enable_unix_time) {
                strftime(first_seen_str, sizeof(first_seen_str), "%s", first_seen_tm);
                strftime(last_seen_str, sizeof(last_seen_str), "%s", last_seen_tm);
            } else {
                strftime(first_seen_str, sizeof(first_seen_str), "%m/%d/%Y %H:%M:%S", first_seen_tm);
                strftime(last_seen_str, sizeof(last_seen_str), "%m/%d/%Y %H:%M:%S", last_seen_tm);
            }
            fprintf(output_file, "{ \"Type\": \"ARP Summary\", \"Timestamp\": \"%s\", \"IP\": \"%s\", \"MAC\": \"%s\", \"First Seen\": \"%s\", \"Last Seen\": \"%s\", \"Count\": %d, \"Organization\": \"%s\", \"DNS Name\": \"%s\" }\n",
                    enable_unix_time ? first_seen_str : arp_table[i].timestamp,
                    arp_table[i].ip, arp_table[i].mac,
                    enable_unix_time ? first_seen_str : arp_table[i].timestamp,
                    enable_unix_time ? last_seen_str : arp_table[i].timestamp,
                    arp_table[i].count, arp_table[i].organization, arp_table[i].dns_name);
            fflush(output_file); // Flush the output stream
        }
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    struct ether_arp *arp_packet;

    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ether_arp)) {
        return; // Packet is too small
    }

    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP) {
        return; // Not an ARP packet
    }

    arp_packet = (struct ether_arp *)(packet + sizeof(struct ether_header));
    if (ntohs(arp_packet->ea_hdr.ar_op) != ARPOP_REPLY) {
        return; // Not an ARP reply
    }

    char src_ip[INET_ADDRSTRLEN], src_mac[18], dns_name[256];
    const char* organization = lookup_oui(arp_packet->arp_sha);

    inet_ntop(AF_INET, arp_packet->arp_spa, src_ip, INET_ADDRSTRLEN);
    mac_to_str(arp_packet->arp_sha, src_mac);
    perform_dns_lookup(src_ip, dns_name);

    time_t now = time(NULL);
    if (update_arp_table(src_ip, arp_packet->arp_sha, now)) {
        struct tm* timestamp_tm = localtime(&now);
        char timestamp_str[64];
        if (enable_unix_time) {
            strftime(arp_table[arp_table_size - 1].timestamp, sizeof(arp_table[arp_table_size - 1].timestamp), "%s", timestamp_tm);
            snprintf(timestamp_str, sizeof(timestamp_str), "%ld", now);
        } else {
            strftime(arp_table[arp_table_size - 1].timestamp, sizeof(arp_table[arp_table_size - 1].timestamp), "%m/%d/%Y %H:%M:%S", timestamp_tm);
            snprintf(timestamp_str, sizeof(timestamp_str), "%s", arp_table[arp_table_size - 1].timestamp);
        }
        fprintf(output_file, "{ \"Type\": \"Live ARP\", \"Timestamp\": \"%s\", \"IP\": \"%s\", \"MAC\": \"%s\", \"Organization\": \"%s\", \"DNS Name\": \"%s\" }\n",
                timestamp_str,
                src_ip, src_mac, organization, dns_name);
        fflush(output_file); // Flush the output stream
    }
}

int main(int argc, char **argv) {
    atexit(atexit_handler); // Ensure cleanup is called on exit
    pthread_mutex_init(&lock, NULL);

    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = NULL;
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "arp";
    bpf_u_int32 net = 0, mask = 0;
    pthread_t summary_thread;
    bool summary_thread_created = false;

    // Argument parsing
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [-h] [--no-dns] [--summary] [--unix-time] [-o <output_file>] [--oui-file <file>] <interface>\n", argv[0]);
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[i], "--no-dns") == 0) {
            enable_dns_lookup = false;
        } else if (strcmp(argv[i], "--summary") == 0) {
            enable_summary = true;
        } else if (strcmp(argv[i], "--unix-time") == 0) {
            enable_unix_time = true;
        } else if (strcmp(argv[i], "-o") == 0 && (i + 1) < argc) {
            output_file = fopen(argv[++i], "w");
            if (output_file == NULL) {
                // Check if the filename contains a path
                const char* filename = argv[i];
                const char* path_separator = strrchr(filename, '/');
                if (path_separator == NULL) {
                    // No path specified, prepend current directory path
                    char cwd[1024];
                    if (getcwd(cwd, sizeof(cwd)) != NULL) {
                        char fullpath[2048];
                        snprintf(fullpath, sizeof(fullpath), "%s/%s", cwd, filename);
                        output_file = fopen(fullpath, "w");
                    }
                }
                if (output_file == NULL) {
                    fprintf(stderr, "Could not open file %s for writing.\n", argv[i]);
                    exit(EXIT_FAILURE);
                }
            }
        } else if (strcmp(argv[i], "--oui-file") == 0 && (i + 1) < argc) {
            strncpy(oui_file_location, argv[++i], sizeof(oui_file_location) - 1);
            oui_file_location[sizeof(oui_file_location) - 1] = '\0'; // Ensure null-termination
        } else {
            dev = argv[i];
        }
    }

    if (!dev) {
        fprintf(stderr, "Network device not specified. Use -h for help.\n");
        exit(EXIT_FAILURE);
    }

    if (!output_file) {
        output_file = stdout; // Default to stdout if not specified
    }

    load_oui_data();

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (enable_summary) {
        if (pthread_create(&summary_thread, NULL, print_summary, NULL) == 0) {
            summary_thread_created = true;
        } else {
            fprintf(stderr, "Could not create the summary thread.\n");
            exit(EXIT_FAILURE);
        }
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    if (summary_thread_created) {
        enable_summary_thread = false;
        pthread_join(summary_thread, NULL);
    }

    cleanup_resources();

    return 0;
}
