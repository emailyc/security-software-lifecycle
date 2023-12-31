#include <stdarg.h>
#include "stdlib.h"
#include "string.h"
#include "emdns.h"
#include "stdio.h"
#include "stdlib.h"
#include "arpa/inet.h"

#define PACK8(p, val)    ((*(uint8_t*)p) = (val));  p++;
#define PACK16(p, val)   ((*(uint16_t*)p) = (val)); p+=2;
#define PACK32(p, val)   ((*(uint32_t*)p) = (val)); p+=4;
#define UNPACK8(p, val)  val =  (*((uint8_t*)(p))); p++;
#define UNPACK16(p, val) val = (*((uint16_t*)(p))); p+=2;
#define UNPACK32(p, val) val = (*((uint32_t*)(p))); p+=4;
#define UNPACK8(p, val)  val =  (*((uint8_t*)(p))); p++;
#define UNPACK16_N2H(p, val) val = ntohs(*((uint16_t*)(p))); p+=2;
#define UNPACK32_N2H(p, val) val = ntohl(*((uint32_t*)(p))); p+=4;
#define MOVE(p, count) p+=(count);

const char* hexBytes[256] = {
        "00", "01", "02", "03", "04", "05", "06", "07",
        "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
        "10", "11", "12", "13", "14", "15", "16", "17",
        "18", "19", "1A", "1B", "1C", "1D", "1E", "1F",
        "20", "21", "22", "23", "24", "25", "26", "27",
        "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
        "30", "31", "32", "33", "34", "35", "36", "37",
        "38", "39", "3A", "3B", "3C", "3D", "3E", "3F",
        "40", "41", "42", "43", "44", "45", "46", "47",
        "48", "49", "4A", "4B", "4C", "4D", "4E", "4F",
        "50", "51", "52", "53", "54", "55", "56", "57",
        "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
        "60", "61", "62", "63", "64", "65", "66", "67",
        "68", "69", "6A", "6B", "6C", "6D", "6E", "6F",
        "70", "71", "72", "73", "74", "75", "76", "77",
        "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",
        "80", "81", "82", "83", "84", "85", "86", "87",
        "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
        "90", "91", "92", "93", "94", "95", "96", "97",
        "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",
        "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7",
        "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",
        "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7",
        "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
        "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7",
        "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",
        "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7",
        "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",
        "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7",
        "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
        "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7",
        "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"
};

typedef struct emdns_record_t {
    struct emdns_record_t* next;
    dns_record_t record_type;
#ifdef EMDNS_SUPPORT_ALL_CLASSES
    dns_class_t record_class;
#endif    
    char* domain;
    char* response;
    uint32_t ttl;
    uint16_t length;
} emdns_record_t;


static emdns_record_t* records;

static char* _to_dns_string(char* domain);
static uint32_t _to_ip_value(char* ip);
static void pack_resource_record(emdns_record_t* record, char** response_buffer);

#ifdef EMDNS_SUPPORT_ALL_CLASSES
static emdns_record_t* _find_record(char* domain, dns_record_t record_type, dns_class_t record_class, emdns_record_t* start);
#else
static emdns_record_t* _find_record(char* domain, dns_record_t record_type, emdns_record_t* start);
#endif

#ifdef EMDNS_SUPPORT_ALL_CLASSES

int emdns_add_record(char* domain, dns_record_t record_type, dns_class_t record_class, char* response, uint32_t ttl) {
#else

int emdns_add_record(char* domain, dns_record_t record_type, char* response, uint32_t ttl) {
#endif    

#ifdef EMDNS_ENABLE_LOGGING    
    printf("Added record.\n");
#endif

    emdns_record_t* entry = malloc(sizeof (emdns_record_t));
    if (entry != 0) {
        entry->domain = _to_dns_string(domain);
        entry->record_type = record_type;
        entry->ttl = ttl;
#ifdef EMDNS_SUPPORT_ALL_CLASSES
        entry->record_class = record_class;
#endif        

        switch (record_type) {
            case RecordA:
                entry->length = sizeof (uint32_t);
                entry->response = malloc(entry->length);
                *((uint32_t*) (entry->response)) = htonl(_to_ip_value(response));
                break;

            case RecordCNAME:
            case RecordNS:
            case RecordPTR:
                entry->response = _to_dns_string(response);
                entry->length = strlen(entry->response) + 1;
                break;

            case RecordMX:
                entry->length = sizeof (uint16_t) + strlen(response) + 2;
                uint16_t preference = 0;
                entry->response = malloc(entry->length);
                int res = sscanf(response, "%hd %s", &preference, (entry->response + 2));

                *((uint16_t*) entry->response) = htons(preference);
                char* dns_str = _to_dns_string(entry->response + 2);
                strcpy(entry->response + 2, dns_str);

                entry->length -= (strlen(response) - strlen(dns_str) + 1);
                free(dns_str);

                break;

            case RecordSOA:
            {
                char* server = malloc(256);
                char* mail = malloc(256);
                uint32_t serial, refresh, retry, expire, minimum;

                int res = sscanf(response, "%s %s %d %d %d %d %d", server, mail, &serial, &refresh, &retry, &expire, &minimum);
                entry->length = strlen(server) + 2 + strlen(mail) + 2 + (5 * sizeof (uint32_t));
                entry->response = malloc(entry->length);

                char* server_dns = _to_dns_string(server);
                char* mail_dns = _to_dns_string(mail);
                strcpy(entry->response, server_dns);
                strcpy(entry->response + strlen(server_dns) + 1, mail_dns);
                uint8_t* p = entry->response + strlen(server_dns) + strlen(mail_dns) + 2;
                *((uint32_t*) (p + 0)) = htonl(serial);
                *((uint32_t*) (p + 4)) = htonl(refresh);
                *((uint32_t*) (p + 8)) = htonl(retry);
                *((uint32_t*) (p + 12)) = htonl(expire);
                *((uint32_t*) (p + 16)) = htonl(minimum);

                entry->length = strlen(server_dns) + 1 + strlen(mail_dns) + 1 + (5 * sizeof (uint32_t));

                free(server);
                free(mail);
                free(server_dns);
                free(mail_dns);
            }
                break;

            case RecordTXT:
                entry->length = strlen(response) + 1;
                entry->response = malloc(entry->length);
                *((uint8_t*) entry->response) = strlen(response);
                memcpy(entry->response, response, entry->length);
                break;
        }

        entry->next = records;
        records = entry;
        return 0;
    }

    return -1;
}

#ifdef EMDNS_SUPPORT_ALL_CLASSES

int emdns_remove_record(char* domain, dns_record_t record_type, dns_class_t record_class) {
#else

int emdns_remove_record(char* domain, dns_record_t record_type) {
#endif    
    char* dns_string = _to_dns_string(domain);
    emdns_record_t* ptr_record = records;
    emdns_record_t* ptr_prev = 0;
    uint8_t records_removed = 0;
    while (ptr_record != 0) {
        if (ptr_record->record_type == record_type &&
#ifdef EMDNS_SUPPORT_ALL_CLASSES
            ptr_record->record_class == record_class &&
#endif                
            strcmp(ptr_record->domain, dns_string) == 0) {
            if (ptr_record == records) {
                records = ptr_record->next;
            }
            else {
                ptr_prev->next = ptr_record->next;
            }
            emdns_record_t* next = ptr_record->next;
            free(ptr_record);
            records_removed++;
            ptr_record = next;
            continue;
        }
        ptr_prev = ptr_record;
        ptr_record = ptr_record->next;
    }
    free(dns_string);
    return records_removed;
}

static void dns_log(const char *source, const char *func, int line, char *message, ...)
{
    va_list arg_list;
    char buffer[1000];

    va_start(arg_list, message);
    vsnprintf(buffer, 1000, message, arg_list);
    va_end(arg_list);

    printf("%s[%s][%d]\t%s\n", source, func, line, buffer);
}

#define DEBUG(message, ...)     dns_log(__FILE__, __FUNCTION__, __LINE__, message, ##__VA_ARGS__)

static void _log_request_string(char* request_buffer) {
    static char request_buffer_string[257];
    dns_header_t request;

    memcpy(&request, request_buffer, sizeof(request));

    DEBUG("--------------DUMP DNS PACKET-------------");
    DEBUG("request.id=%hu", request.id);
    DEBUG("request.flags=%hu", request.flags);
    DEBUG("request.qdcount=%hu", request.qdcount);
    DEBUG("request.ancount=%hu", request.ancount);
    DEBUG("request.nscount=%hu", request.nscount);
    DEBUG("request.arcount=%hu", request.arcount);

    for(int i = sizeof(dns_header_t); i<128; i++) {
        const char *hex_str = hexBytes[(unsigned char) request_buffer[i]];
        request_buffer_string[i*2] = hex_str[0];
        request_buffer_string[i*2 + 1] = hex_str[1];
        printf("%c", request_buffer_string[i*2]);
        printf("%c", request_buffer_string[i*2]);
    }
    request_buffer_string[256] = '\0';
    DEBUG("payload=0x%s\n", request_buffer_string);
}

static char* _to_dns_string(char* domain) {
    char* dns_string = malloc(2 + strlen(domain));
    char* p_dns_string = dns_string + 1;
    char* p_length_byte = dns_string;
    *p_length_byte = 0;

    while (*domain != '\0') {
        if (*domain != '.') {
            *p_dns_string = *domain;
            (*p_length_byte)++;
        }
        else {
            p_length_byte = p_dns_string;
            *p_length_byte = 0;
        }
        domain++;
        p_dns_string++;
    }
    *p_dns_string = '\0';
    return dns_string;
}

static uint32_t _to_ip_value(char* ip) {
    uint32_t ip_value = 0x00000000;
    char buf[4];
    char* p_buf = buf;
    char* p_ip = ip;
    uint8_t i = 4;
    while (i--) {
        while (*p_ip != '.' && *p_ip != '\0') {
            *p_buf = *p_ip;
            p_buf++;
            p_ip++;
        }
        (*p_buf) = '\0';
        ip_value = (ip_value << 8) | atoi(buf);
        p_buf = buf;
        p_ip++;
    }
    return ip_value;
}

#ifdef EMDNS_SUPPORT_ALL_CLASSES

static emdns_record_t* _find_record(char* domain, dns_record_t record_type, dns_class_t record_class, emdns_record_t* start) {
#else

static emdns_record_t* _find_record(char* domain, dns_record_t record_type, emdns_record_t* start) {
#endif
    emdns_record_t* ptr_record = start;
    while (ptr_record != 0) {
        if (ptr_record->record_type == record_type &&
#ifdef EMDNS_SUPPORT_ALL_CLASSES
            ptr_record->record_class == record_class &&
#endif                
            strcmp(ptr_record->domain, domain) == 0) {
            return ptr_record;
        }
        ptr_record = ptr_record->next;
    }
    return 0;
}

void emdns_resolve_raw(char* request_buffer, char* response_buffer, uint16_t response_max, uint16_t* answer_len) {

#ifdef EMDNS_ENABLE_LOGGING
    _log_request_string(request_buffer);
#endif

    dns_header_t* request = (dns_header_t*) request_buffer;
    dns_header_t* response = (dns_header_t*) response_buffer;

    // prepare header
    memcpy(response_buffer, request_buffer, sizeof (dns_header_t));
    MOVE(request_buffer, sizeof (dns_header_t));
    MOVE(response_buffer, sizeof (dns_header_t));

    response->flags = htons(FlagQR | FlagAA); // set response and AA flag
    response->qdcount = htons(0);
    response->ancount = htons(0);
    response->nscount = htons(0);
    response->arcount = htons(0);

    // prepare domain
    uint8_t* requested_domain = request_buffer;
    uint8_t len = strlen(request_buffer);

    MOVE(request_buffer, len + 1);

    dns_record_t type;
    dns_class_t class;
    UNPACK16_N2H(request_buffer, type);
    UNPACK16_N2H(request_buffer, class);

    emdns_record_t* record = records;
    while (1) {
#ifdef EMDNS_SUPPORT_ALL_CLASSES
        emdns_record_t* record = _find_record(requested_domain, type, class, record);
#else
        record = (class == ClassIN ? _find_record(requested_domain, type, record) : 0);
#endif
        if (record == 0) {
#ifndef EMDNS_DISABLE_ALIAS_RESOLVING
            if (type != RecordCNAME) {
                // try to find alias
#ifdef EMDNS_SUPPORT_ALL_CLASSES                
                emdns_record_t* alias = _find_record(requested_domain, RecordCNAME, class, records);
#else
                emdns_record_t* alias = _find_record(requested_domain, RecordCNAME, records);
#endif                
                if (alias) {
                    response->ancount++;
                    pack_resource_record(alias, &response_buffer);
                    requested_domain = alias->response;
                    record = records;
                    continue;
                }
            }
#endif                        
            break;
        }
        else {
            response->ancount++;
            pack_resource_record(record, &response_buffer);
            record = record->next;
        }
    }

#ifdef EMDNS_ENABLE_LOGGING
    printf("%d records found.\n", response->ancount);
#endif      

    if (response->ancount == 0) {
        response->flags = htons(FlagQR | FlagAA | FlagErrName);
        *answer_len = sizeof (dns_header_t);
    }
    else {
        response->ancount = htons(response->ancount);
        *answer_len = (response_buffer - (char*) response);
    }
}

static void pack_resource_record(emdns_record_t* record, char** response_buffer) {
    if (record != 0) {
        uint16_t len = strlen(record->domain);
        memcpy(*response_buffer, record->domain, len + 1);
        MOVE(*response_buffer, len + 1);

        PACK16(*response_buffer, htons(record->record_type));
#ifdef EMDNS_SUPPORT_ALL_CLASSES        
        PACK16(*response_buffer, htons(record->record_class));
#else
        PACK16(*response_buffer, htons(ClassIN));
#endif
        PACK32(*response_buffer, htonl(record->ttl));
        PACK16(*response_buffer, htons(record->length));

        memcpy(*response_buffer, record->response, record->length);
        MOVE(*response_buffer, record->length);
    }
}
