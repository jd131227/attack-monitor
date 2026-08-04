/*
 * monitor_core.h - Core logic for the server attack-detection monitor (C side)
 *
 * Role: implement the central logic in C - log parsing, per-IP aggregation,
 *       threshold evaluation, and allow-list matching. The Python driver calls
 *       these functions through ctypes.
 *
 * Design (per spec 2.1 / 2.2):
 *   - Data is passed between functions by pointer wherever practical.
 *   - Aggregation state is held in a linked list (ip_stat nodes) and walked
 *     recursively. Every recursion has an explicit base case.
 *   - Every dynamically allocated node is tracked by pointer and always freed
 *     (no leaks).
 */
#ifndef MONITOR_CORE_H
#define MONITOR_CORE_H

#include <stddef.h>

#define IP_STR_MAX 64   /* long enough to hold both IPv4 and IPv6 strings */

/*
 * 追跡する個別 IP 数の上限（連結リストの最大長）。
 * リストの走査・集計・解放は再帰で行う（仕様 2.2）。再帰の深さはリスト長に等しいため、
 * 大量の送信元 IP（巨大なコネクションフラッド／分散総当たり）でリストが青天井に伸びると
 * スタックを食い潰してクラッシュしうる。仕様 2.2 の「深さの暴走を防ぐ」要件に従い、
 * 追跡数に上限を設けて再帰深さを有界化する。上限到達後の新規 IP は集計しないが、
 * その時点で既に「大量送信元」でありしきい値判定には十分。
 */
#define MAX_TRACKED_IPS 4096

/*
 * ip_stat: aggregation node for one source IP (an element of the linked list).
 *  - Following `next` lets us walk every IP recursively.
 */
typedef struct ip_stat {
    char ip[IP_STR_MAX];     /* source IP (string) */
    long fail_count;         /* count within the time window (SSH failures, or
                                connection count when reused for conn tallying) */
    long last_seen;          /* last observed epoch second (used for windowing) */
    struct ip_stat *next;    /* pointer to next node (linked list) */
} ip_stat;

/*
 * stat_table: the whole aggregation table. `head` is the head pointer of the
 * linked list.
 */
typedef struct {
    ip_stat *head;           /* head of the linked list (NULL = empty) */
    long window_seconds;     /* sliding-window width in seconds */
} stat_table;

/* ---- Lifecycle ---- */

/* Create a table and return its pointer. Returns NULL on failure. */
stat_table *st_create(long window_seconds);

/* Recursively free the table and every node (leak prevention). */
void st_free(stat_table *t);

/* ---- Aggregation ---- */

/*
 * Feed one SSH log line. If it is a failure event, increment that IP's counter.
 * Returns 1 when the line was counted as a failure, 0 otherwise.
 * `line` is the text to parse, `now` is the current epoch second.
 */
int st_ingest_line(stat_table *t, const char *line, long now);

/*
 * Recursively walk and remove entries that have fallen out of the time window.
 * Relative to `now`, nodes with (now - last_seen) > window are removed.
 */
void st_expire(stat_table *t, long now);

/*
 * Return how many IPs are at or above `threshold`.
 * If `out_buf` is non-NULL, the offending IPs are written into it, one
 * "ip (count)" per line, up to `buf_size` bytes.
 */
int st_count_over_threshold(const stat_table *t, long threshold,
                            char *out_buf, size_t buf_size);

/* ---- IP validation / allow-list matching (spec 4.5.4) ---- */

/*
 * Classify an IP string.
 * Returns: 4 = IPv4, 6 = IPv6, 1 = CIDR (IPv4/IPv6), 0 = invalid.
 */
int ip_classify(const char *s);

/*
 * Recursively check whether `needle` (a single IP) matches any allow entry
 * (plain IP or CIDR) contained in `list`.
 * `list` is the newline-separated allow-entry text (contents of the allow-IP
 * file). Returns 1 on match, 0 otherwise.
 */
int ip_allowed(const char *needle, const char *list);

/* ---- Connection-count aggregation (spec 3.2: suspicious source IPs) ---- */

/*
 * Given `ip_list` (one source IP per line, extracted from `ss` by the Python
 * driver), tally how many connections each source IP has and return how many
 * distinct IPs reach `threshold` or more.
 *
 * Any IP that matches `whitelist` (newline-separated allow/whitelist entries,
 * may be NULL or "") is excluded from the result - it is a trusted peer.
 *
 * If `out_buf` is non-NULL the offending IPs are written, one "ip (count)" per
 * line, up to `buf_size` bytes.
 *
 * The internal tally list is built with malloc and freed recursively before
 * returning, so there is no leak.
 */
int conn_over_threshold(const char *ip_list, const char *whitelist,
                        long threshold, char *out_buf, size_t buf_size);

#endif /* MONITOR_CORE_H */
