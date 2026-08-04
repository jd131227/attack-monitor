/*
 * monitor_core.c - Core logic for the server attack-detection monitor (C side)
 *
 * Required techniques (spec 2.2):
 *   - Pointers: nodes are linked, passed, and allocated entirely by pointer.
 *   - Recursion: walking, freeing, counting the linked list and matching CIDR
 *                ranges are implemented recursively. Every recursion has an
 *                explicit base case.
 */
#include "monitor_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* ============================================================
 * Lifecycle
 * ============================================================ */

stat_table *st_create(long window_seconds) {
    /* Allocate the table itself and return it by pointer. */
    stat_table *t = (stat_table *)malloc(sizeof(stat_table));
    if (t == NULL) return NULL;          /* allocation failure -> NULL */
    t->head = NULL;
    t->window_seconds = window_seconds;
    return t;
}

/* Recursively free the linked list (base case: node == NULL). */
static void free_nodes(ip_stat *node) {
    if (node == NULL) return;            /* base case */
    free_nodes(node->next);              /* descend to the tail, then free */
    free(node);
}

void st_free(stat_table *t) {
    if (t == NULL) return;
    free_nodes(t->head);                 /* recursively free every node */
    free(t);
}

/* ============================================================
 * Aggregation
 * ============================================================ */

/* Return the node for `ip` by pointer. If absent, allocate one and insert at
 * the head. Returns NULL when the per-table IP cap is reached (keeps the list
 * length - and therefore the recursion depth over it - bounded). */
static ip_stat *find_or_add(stat_table *t, const char *ip) {
    ip_stat *cur = t->head;
    long count = 0;                      /* count nodes during the search (free) */
    while (cur != NULL) {                /* linear search of existing nodes */
        if (strncmp(cur->ip, ip, IP_STR_MAX) == 0) return cur;
        count++;
        cur = cur->next;
    }
    /* Cap the distinct-IP count so the recursive walk/expire/free over this list
     * can never overflow the stack under a huge distributed brute-force. */
    if (count >= MAX_TRACKED_IPS) return NULL;
    /* Not found: allocate a new node (linked by pointer). */
    ip_stat *node = (ip_stat *)malloc(sizeof(ip_stat));
    if (node == NULL) return NULL;
    strncpy(node->ip, ip, IP_STR_MAX - 1);
    node->ip[IP_STR_MAX - 1] = '\0';
    node->fail_count = 0;
    node->last_seen = 0;
    node->next = t->head;                /* head insertion, O(1) */
    t->head = node;
    return node;
}

/* Copy the token starting at `p` (the source-IP candidate) into `out`, stopping
 * at ANY whitespace so a trailing '\n'/'\r'/'\t' from f.readlines() never gets
 * baked into the key. Returns the address just past the copied token. */
static const char *copy_ip_token(const char *p, char *out, size_t out_sz) {
    size_t i = 0;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r' &&
           i < out_sz - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return p;
}

/*
 * Extract the *real* source IP from an sshd failure line.
 *
 * Targets "Failed password ... from <IP> port ..." / "Invalid user <name> from
 * <IP> port ...". The username/`for <user>` field is ATTACKER-CONTROLLED and
 * OpenSSH keeps spaces inside it, so a login as `x from 9.9.9.9 port 1` yields
 * "Invalid user x from 9.9.9.9 port 1 from <realip> port 54321". Anchoring on
 * the FIRST " from " would let the attacker pin failures onto a spoofed/innocent
 * IP (false alerts) or onto garbage (hiding the real source).
 *
 * Defence: the genuine source field is the LAST " from <token> port " in the
 * line (sshd always appends it after the username), and the token must be a
 * real IP. We therefore scan EVERY " from ", and keep the last candidate whose
 * token both classifies as an IP and is immediately followed by " port ". If
 * none is port-anchored (unusual formats) we fall back to the last token that
 * still validates as an IP, so a malformed/garbage key is never stored.
 *
 * On success copies the IP into `out` and returns 1; otherwise 0.
 */
static int extract_failed_ip(const char *line, char *out, size_t out_sz) {
    if (strstr(line, "Failed password") == NULL &&
        strstr(line, "Invalid user") == NULL) {
        return 0;                        /* not a failure event */
    }
    char cand[IP_STR_MAX];
    int have_port_anchored = 0;          /* found a " from <ip> port " match? */
    out[0] = '\0';

    const char *p = strstr(line, " from ");
    while (p != NULL) {
        const char *tok = p + 6;         /* skip past " from " */
        const char *after = copy_ip_token(tok, cand, sizeof(cand));
        if (cand[0] != '\0' && ip_classify(cand) != 0) {
            int port_anchored = (strncmp(after, " port ", 6) == 0);
            /* Prefer the last port-anchored hit; otherwise remember the last
             * IP-shaped token as a fallback. A port-anchored hit always wins
             * over a non-anchored one. snprintf always null-terminates, so the
             * copy is safe and warning-free. */
            if (port_anchored || !have_port_anchored) {
                snprintf(out, out_sz, "%s", cand);
                if (port_anchored) have_port_anchored = 1;
            }
        }
        p = strstr(p + 6, " from ");     /* advance to the next " from " */
    }
    return (out[0] != '\0') ? 1 : 0;
}

int st_ingest_line(stat_table *t, const char *line, long now) {
    if (t == NULL || line == NULL) return 0;
    char ip[IP_STR_MAX];
    if (!extract_failed_ip(line, ip, sizeof(ip))) return 0;
    ip_stat *node = find_or_add(t, ip);
    if (node == NULL) return 0;
    node->fail_count += 1;
    node->last_seen = now;
    return 1;
}

/*
 * Recursively drop expired nodes and return the new head pointer.
 * Base case: node == NULL.
 */
static ip_stat *expire_rec(ip_stat *node, long now, long window) {
    if (node == NULL) return NULL;       /* base case */
    node->next = expire_rec(node->next, now, window);  /* process tail first */
    if ((now - node->last_seen) > window) {
        ip_stat *survivor = node->next;  /* this node is out of window -> free */
        free(node);
        return survivor;
    }
    return node;
}

void st_expire(stat_table *t, long now) {
    if (t == NULL) return;
    t->head = expire_rec(t->head, now, t->window_seconds);
}

/*
 * Recursively count nodes at/over the threshold, optionally appending each to
 * `out_buf`. Returns the over-threshold count for this sublist.
 */
static int count_rec(const ip_stat *node, long threshold,
                     char *out_buf, size_t buf_size) {
    if (node == NULL) return 0;          /* base case */
    int rest = count_rec(node->next, threshold, out_buf, buf_size);
    if (node->fail_count >= threshold) {
        if (out_buf != NULL) {
            char line[IP_STR_MAX + 32];
            snprintf(line, sizeof(line), "%s (%ld)\n",
                     node->ip, node->fail_count);
            /* Check remaining space and concatenate safely. */
            size_t used = strlen(out_buf);
            if (used + strlen(line) < buf_size) {
                strcat(out_buf, line);
            }
        }
        return rest + 1;
    }
    return rest;
}

int st_count_over_threshold(const stat_table *t, long threshold,
                            char *out_buf, size_t buf_size) {
    if (t == NULL) return 0;
    if (out_buf != NULL && buf_size > 0) out_buf[0] = '\0';
    return count_rec(t->head, threshold, out_buf, buf_size);
}

/* ============================================================
 * IP validation / allow-list matching (spec 4.5.4)
 * ============================================================ */

/* Strip the "/n" prefix length, copy the address part into `addr`, and return
 * the prefix (or -1 when absent). */
static int split_cidr(const char *s, char *addr, size_t addr_sz, int *has_cidr) {
    const char *slash = strchr(s, '/');
    *has_cidr = (slash != NULL);
    size_t len = slash ? (size_t)(slash - s) : strlen(s);
    if (len >= addr_sz) len = addr_sz - 1;
    memcpy(addr, s, len);
    addr[len] = '\0';
    return slash ? atoi(slash + 1) : -1;
}

int ip_classify(const char *s) {
    if (s == NULL || *s == '\0') return 0;
    char addr[IP_STR_MAX];
    int has_cidr = 0;
    int prefix = split_cidr(s, addr, sizeof(addr), &has_cidr);

    struct in6_addr v6;
    struct in_addr v4;
    int is_v4 = inet_pton(AF_INET, addr, &v4) == 1;
    int is_v6 = inet_pton(AF_INET6, addr, &v6) == 1;
    if (!is_v4 && !is_v6) return 0;      /* address part is invalid */

    if (has_cidr) {
        int maxp = is_v4 ? 32 : 128;
        if (prefix < 0 || prefix > maxp) return 0;  /* prefix out of range */
        return 1;                         /* valid CIDR */
    }
    return is_v4 ? 4 : 6;
}

/* Convert an IPv4 string to a 32-bit integer (network byte order). 0 on fail. */
static int v4_to_u32(const char *s, unsigned int *out) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return 0;
    *out = a.s_addr;
    return 1;
}

/* IPv4 CIDR match: compare only the top `prefix` bits. */
static int v4_cidr_match(const char *ip, const char *net, int prefix) {
    unsigned int a, b;
    if (!v4_to_u32(ip, &a) || !v4_to_u32(net, &b)) return 0;
    if (prefix <= 0) return 1;
    if (prefix > 32) prefix = 32;
    /* Values are in network byte order; convert to host order before masking. */
    unsigned int ha = ntohl(a), hb = ntohl(b);
    unsigned int mask = (prefix == 32) ? 0xFFFFFFFFu
                                       : ~((1u << (32 - prefix)) - 1);
    return (ha & mask) == (hb & mask);
}

/*
 * IPv6 CIDR match: compare the top `prefix` bits across the 16 address bytes.
 * Network calculation, so byte/bit operations are used here intentionally
 * (allowed by the spec for this case).
 */
static int v6_cidr_match(const char *ip, const char *net, int prefix) {
    struct in6_addr a, b;
    if (inet_pton(AF_INET6, ip, &a) != 1) return 0;
    if (inet_pton(AF_INET6, net, &b) != 1) return 0;
    if (prefix <= 0) return 1;
    if (prefix > 128) prefix = 128;
    int full_bytes = prefix / 8;         /* whole bytes that must match exactly */
    int rem_bits = prefix % 8;           /* leftover high bits in the next byte */
    if (full_bytes > 0 && memcmp(a.s6_addr, b.s6_addr, full_bytes) != 0) return 0;
    if (rem_bits != 0) {
        unsigned char mask = (unsigned char)(0xFF << (8 - rem_bits));
        if ((a.s6_addr[full_bytes] & mask) != (b.s6_addr[full_bytes] & mask))
            return 0;
    }
    return 1;
}

/* Whether the single allow entry `entry` matches `needle`. */
static int match_entry(const char *needle, const char *entry) {
    char addr[IP_STR_MAX];
    int has_cidr = 0;
    int prefix = split_cidr(entry, addr, sizeof(addr), &has_cidr);
    if (!has_cidr) {
        return strcmp(needle, entry) == 0;   /* exact match */
    }
    /* CIDR: match by family. A v4 needle only matches a v4 network, and a v6
     * needle only matches a v6 network. */
    int ncls = ip_classify(needle);
    int ecls = ip_classify(addr);            /* 4 or 6 for the network address */
    if (ncls == 4 && ecls == 4) {
        return v4_cidr_match(needle, addr, prefix);
    }
    if (ncls == 6 && ecls == 6) {
        return v6_cidr_match(needle, addr, prefix);
    }
    return 0;                                /* family mismatch -> no match */
}

/*
 * Recursively walk the newline-separated allow list and match.
 * Each iteration cuts out one line up to the next newline and recurses on the
 * rest. Base case: end of string ('\0').
 */
static int allowed_rec(const char *needle, const char *pos) {
    while (*pos == '\n' || *pos == ' ' || *pos == '\t' || *pos == '\r') pos++;
    if (*pos == '\0') return 0;          /* base case: reached the end, no match */

    /* Cut out one line. */
    char entry[128];
    size_t i = 0;
    const char *p = pos;
    while (*p && *p != '\n' && i < sizeof(entry) - 1) {
        if (*p != '\r') entry[i++] = *p;
        p++;
    }
    entry[i] = '\0';

    /* Trim a trailing inline comment ("ip  # note" / "ip# note") so the entry
     * is just the address. Also trims trailing whitespace. */
    char *hash = strchr(entry, '#');
    if (hash != NULL) *hash = '\0';
    size_t end = strlen(entry);
    while (end > 0 && (entry[end - 1] == ' ' || entry[end - 1] == '\t')) {
        entry[--end] = '\0';
    }

    /* Skip comment lines and blank lines. */
    if (entry[0] != '\0') {
        if (match_entry(needle, entry)) return 1;
    }
    return allowed_rec(needle, p);       /* recurse on the remainder */
}

int ip_allowed(const char *needle, const char *list) {
    if (needle == NULL || list == NULL) return 0;
    if (ip_classify(needle) == 0) return 0;   /* needle itself is invalid */
    return allowed_rec(needle, list);
}

/* ============================================================
 * Connection-count aggregation (spec 3.2: suspicious source IPs)
 * ============================================================ */

/*
 * Small standalone tally list used only by conn_over_threshold(). Kept separate
 * from stat_table so connection counting never disturbs the SSH-failure state.
 */
typedef struct conn_node {
    char ip[IP_STR_MAX];
    long count;
    struct conn_node *next;
} conn_node;

/* Recursively free the tally list (base case: node == NULL). */
static void free_conn_nodes(conn_node *node) {
    if (node == NULL) return;            /* base case */
    free_conn_nodes(node->next);
    free(node);
}

/* Find/insert a tally node for `ip` and return it by pointer (head insertion).
 * Returns NULL either when the distinct-IP cap is hit (a new IP is simply not
 * tracked) or on allocation failure; `*oom` distinguishes the two so the caller
 * can keep tallying past the cap but abort on a real OOM. */
static conn_node *conn_find_or_add(conn_node **head, const char *ip, int *oom) {
    conn_node *cur = *head;
    long count = 0;                      /* count nodes during the search (free) */
    while (cur != NULL) {
        if (strncmp(cur->ip, ip, IP_STR_MAX) == 0) return cur;
        count++;
        cur = cur->next;
    }
    /* Bound the distinct-IP tally so the recursive count/free over this list can
     * never overflow the stack during a massive connection flood (the very
     * scenario this detector runs in). Hitting the cap is NOT an error. */
    if (count >= MAX_TRACKED_IPS) return NULL;
    conn_node *node = (conn_node *)malloc(sizeof(conn_node));
    if (node == NULL) { *oom = 1; return NULL; }
    strncpy(node->ip, ip, IP_STR_MAX - 1);
    node->ip[IP_STR_MAX - 1] = '\0';
    node->count = 0;
    node->next = *head;
    *head = node;
    return node;
}

/* Recursively count tally nodes at/over `threshold`, optionally appending each
 * to `out_buf`. Mirrors count_rec() above. Base case: node == NULL. */
static int conn_count_rec(const conn_node *node, long threshold,
                          char *out_buf, size_t buf_size) {
    if (node == NULL) return 0;          /* base case */
    int rest = conn_count_rec(node->next, threshold, out_buf, buf_size);
    if (node->count >= threshold) {
        if (out_buf != NULL) {
            char line[IP_STR_MAX + 32];
            snprintf(line, sizeof(line), "%s (%ld)\n", node->ip, node->count);
            size_t used = strlen(out_buf);
            if (used + strlen(line) < buf_size) {
                strcat(out_buf, line);
            }
        }
        return rest + 1;
    }
    return rest;
}

int conn_over_threshold(const char *ip_list, const char *whitelist,
                        long threshold, char *out_buf, size_t buf_size) {
    if (out_buf != NULL && buf_size > 0) out_buf[0] = '\0';
    if (ip_list == NULL) return 0;

    conn_node *head = NULL;
    const char *p = ip_list;
    int alloc_failed = 0;

    /* Walk the input one line at a time, tallying each source IP. */
    while (*p != '\0') {
        /* Skip leading separators. */
        while (*p == '\n' || *p == ' ' || *p == '\t' || *p == '\r') p++;
        if (*p == '\0') break;

        char ip[IP_STR_MAX];
        size_t i = 0;
        while (*p && *p != '\n' && *p != ' ' && *p != '\t' && *p != '\r' &&
               i < sizeof(ip) - 1) {
            ip[i++] = *p++;
        }
        ip[i] = '\0';
        /* Advance to end of this line so stray trailing tokens are ignored. */
        while (*p && *p != '\n') p++;

        if (ip[0] == '\0') continue;
        if (ip_classify(ip) == 0) continue;          /* skip malformed tokens */
        /* Trusted peers (allow list / whitelist) are excluded from detection. */
        if (whitelist != NULL && ip_allowed(ip, whitelist)) continue;

        conn_node *node = conn_find_or_add(&head, ip, &alloc_failed);
        if (node == NULL) {
            if (alloc_failed) break;     /* real OOM -> stop tallying */
            continue;                    /* cap reached -> skip this new IP */
        }
        node->count += 1;
    }

    int n = alloc_failed ? 0 : conn_count_rec(head, threshold, out_buf, buf_size);
    free_conn_nodes(head);               /* recursively free the tally list */
    return n;
}
