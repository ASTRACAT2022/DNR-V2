#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ldns/ldns.h>

#define PORT 5353
#define TIMEOUT_SEC 5
#define MAX_ITERATIONS 15

typedef struct cache_entry_struct {
    ldns_rr_list *records;
    time_t received_time;
    bool ad_flag;
    uint32_t min_ttl;
} cache_entry;

static ldns_rbtree_t *cache_tree = NULL;

void cache_node_free(ldns_rbnode_t *node, void *arg) {
    (void)arg;
    if (node) {
        cache_entry *entry = (cache_entry *)node->data;
        if (entry) {
            ldns_rr_list_deep_free(entry->records);
            free(entry);
        }
        free((void*)node->key); // Приведение типа для free
        free(node);
    }
}

int cache_key_compare(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

char *create_cache_key(ldns_rdf *qname, ldns_rr_type qtype) {
    char *qname_str = ldns_rdf2str(qname);
    char *key_str;
    asprintf(&key_str, "%s_%d", qname_str, qtype);
    free(qname_str);
    return key_str;
}

void cache_init() {
    if (!cache_tree) {
        cache_tree = ldns_rbtree_create(cache_key_compare);
    }
}

cache_entry *cache_lookup(ldns_rdf *qname, ldns_rr_type qtype) {
    char *key = create_cache_key(qname, qtype);
    ldns_rbnode_t *node = ldns_rbtree_search(cache_tree, key);
    free(key);

    if (node) {
        cache_entry *entry = (cache_entry*)node->data;
        time_t current_time = time(NULL);
        if (difftime(current_time, entry->received_time) < entry->min_ttl) {
            return entry;
        } else {
            ldns_rbtree_delete(cache_tree, node->key);
            cache_node_free(node, NULL);
            return NULL;
        }
    }
    return NULL;
}

void cache_add(ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_list *records, bool ad_flag) {
    if (ldns_rr_list_rr_count(records) == 0) return;

    ldns_rbnode_t *new_node = (ldns_rbnode_t*) malloc(sizeof(ldns_rbnode_t));
    cache_entry *entry = (cache_entry *)malloc(sizeof(cache_entry));
    entry->records = ldns_rr_list_clone(records);
    entry->received_time = time(NULL);
    entry->ad_flag = ad_flag;

    uint32_t min_ttl = ldns_rr_ttl(ldns_rr_list_rr(records, 0));
    for (size_t i = 1; i < ldns_rr_list_rr_count(records); i++) {
        uint32_t current_ttl = ldns_rr_ttl(ldns_rr_list_rr(records, i));
        if (current_ttl < min_ttl) {
            min_ttl = current_ttl;
        }
    }
    entry->min_ttl = min_ttl;

    new_node->key = create_cache_key(qname, qtype);
    new_node->data = entry;

    ldns_rbnode_t* old_node = ldns_rbtree_delete(cache_tree, new_node->key);
    if(old_node) {
        cache_node_free(old_node, NULL);
    }

    ldns_rbtree_insert(cache_tree, new_node);
}

ldns_pkt *resolve_query(ldns_pkt *query_pkt) {
    ldns_pkt *final_pkt = NULL;
    ldns_rr *q_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
    ldns_rdf *q_name = ldns_rr_owner(q_rr);
    ldns_rr_type q_type = ldns_rr_get_type(q_rr);

    cache_entry *cached = cache_lookup(q_name, q_type);
    if (cached) {
        ldns_pkt *cached_pkt = ldns_pkt_new();
        ldns_pkt_set_id(cached_pkt, ldns_pkt_id(query_pkt));
        ldns_pkt_set_qr(cached_pkt, 1);
        ldns_pkt_set_ra(cached_pkt, 1);
        ldns_pkt_set_ad(cached_pkt, cached->ad_flag);
        ldns_pkt_set_rcode(cached_pkt, LDNS_RCODE_NOERROR);
        ldns_rr_list_push_rr(ldns_pkt_question(cached_pkt), ldns_rr_clone(q_rr));
        ldns_pkt_push_rr_list(cached_pkt, LDNS_SECTION_ANSWER, ldns_rr_list_clone(cached->records));
        return cached_pkt;
    }

    ldns_resolver *res;
    if (ldns_resolver_new_frm_file(&res, NULL) != LDNS_STATUS_OK) { return NULL; }

    ldns_resolver_set_dnssec(res, true);

    ldns_rr_list *trust_anchors = ldns_rr_list_new();
    ldns_rr *ksk_rr;
    const char *ksk_str = ". IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=";
    if (ldns_rr_new_frm_str(&ksk_rr, ksk_str, 0, NULL, NULL) != LDNS_STATUS_OK) {
        ldns_resolver_deep_free(res);
        return NULL;
    }
    ldns_rr_list_push_rr(trust_anchors, ksk_rr);
    ldns_resolver_set_dnssec_anchors(res, trust_anchors);


    ldns_pkt *resolved_pkt = ldns_resolver_query(res, q_name, q_type, LDNS_RR_CLASS_IN, LDNS_RD);

    if (resolved_pkt) {
        bool ad_flag = ldns_pkt_ad(resolved_pkt);
        if (ldns_pkt_ancount(resolved_pkt) > 0) {
            cache_add(q_name, q_type, ldns_pkt_answer(resolved_pkt), ad_flag);
        }
        ldns_pkt_set_id(resolved_pkt, ldns_pkt_id(query_pkt));
        ldns_pkt_set_qr(resolved_pkt, 1);
        ldns_pkt_set_ra(resolved_pkt, 1);
        final_pkt = resolved_pkt;
    } else {
        final_pkt = ldns_pkt_new();
        ldns_pkt_set_id(final_pkt, ldns_pkt_id(query_pkt));
        ldns_pkt_set_qr(final_pkt, 1);
        ldns_pkt_set_ra(final_pkt, 1);
        ldns_pkt_set_rcode(final_pkt, LDNS_RCODE_SERVFAIL);
        ldns_rr_list_push_rr(ldns_pkt_question(final_pkt), ldns_rr_clone(q_rr));
    }

    ldns_resolver_deep_free(res);
    return final_pkt;
}

int main(int argc, char **argv) {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    uint8_t buffer[1500];
    ssize_t recv_len;

    cache_init();

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("DNS server listening on port %d...\n", PORT);

    while (1) {
        recv_len = recvfrom(sockfd, buffer, 1500, 0, (struct sockaddr *)&client_addr, &client_len);
        if (recv_len < 0) {
            perror("recvfrom failed");
            continue;
        }

        ldns_pkt *query_pkt;
        if (ldns_wire2pkt(&query_pkt, buffer, recv_len) != LDNS_STATUS_OK) {
            continue;
        }

        ldns_pkt *answer_pkt = resolve_query(query_pkt);

        if (answer_pkt) {
            uint8_t *answer_wire;
            size_t answer_wire_len;
            if (ldns_pkt2wire(&answer_wire, answer_pkt, &answer_wire_len) == LDNS_STATUS_OK) {
                sendto(sockfd, answer_wire, answer_wire_len, 0, (struct sockaddr *)&client_addr, client_len);
                free(answer_wire);
            }
            ldns_pkt_free(answer_pkt);
        }

        ldns_pkt_free(query_pkt);
    }

    close(sockfd);
    return 0;
}