/* test_core.c - unit tests for monitor_core (run with `make test`) */
#include "monitor_core.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

int main(void) {
    /* ---- Aggregation and threshold ---- */
    stat_table *t = st_create(300);
    st_ingest_line(t, "Failed password for root from 10.0.0.9 port 22 ssh2", 1000);
    st_ingest_line(t, "Failed password for root from 10.0.0.9 port 22 ssh2", 1001);
    st_ingest_line(t, "Accepted password for ok from 10.0.0.1", 1002); /* ignored */
    char buf[256];
    int over = st_count_over_threshold(t, 2, buf, sizeof buf);
    printf("over(th=2)=%d buf=[%s]\n", over, buf);
    assert(over == 1);

    /* "Invalid user" is also counted as a failure event. */
    st_ingest_line(t, "Invalid user admin from 10.0.0.50 port 5555", 1003);
    assert(st_count_over_threshold(t, 1, NULL, 0) == 2);

    /* ---- Source-IP spoofing via a crafted username (security) ----
     * An attacker logging in as `x from 9.9.9.9 port 1` makes sshd write a line
     * with an injected " from 9.9.9.9 port 1" BEFORE the real source field.
     * The parser must anchor on the LAST " from <ip> port " (the genuine
     * source), counting 8.8.4.4 - NOT the spoofed 9.9.9.9. */
    stat_table *s = st_create(300);
    st_ingest_line(s,
        "Invalid user x from 9.9.9.9 port 1 from 8.8.4.4 port 54321", 2000);
    char sbuf[256];
    st_count_over_threshold(s, 1, sbuf, sizeof sbuf);
    printf("spoof-test buf=[%s]\n", sbuf);
    assert(strstr(sbuf, "8.8.4.4") != NULL);   /* real source counted */
    assert(strstr(sbuf, "9.9.9.9") == NULL);   /* spoofed source NOT counted */
    /* A failure line carrying no valid IP token must be dropped, not stored as
     * a garbage key. */
    st_ingest_line(s, "Failed password for root from notanip port 22", 2001);
    assert(st_count_over_threshold(s, 1, NULL, 0) == 1);  /* still only 8.8.4.4 */
    st_free(s);

    /* ---- Sliding-window expiry ---- */
    st_expire(t, 2000);
    assert(st_count_over_threshold(t, 1, NULL, 0) == 0);
    st_free(t);

    /* ---- IP classification ---- */
    assert(ip_classify("1.2.3.4") == 4);
    assert(ip_classify("::1") == 6);
    assert(ip_classify("2001:db8::1") == 6);
    assert(ip_classify("10.0.0.0/8") == 1);
    assert(ip_classify("2001:db8::/32") == 1);
    assert(ip_classify("999.1.1.1") == 0);
    assert(ip_classify("1.2.3.4/40") == 0);
    assert(ip_classify("2001:db8::/200") == 0);
    assert(ip_classify("") == 0);
    assert(ip_classify(NULL) == 0);

    /* ---- Allow matching (exact + IPv4 CIDR) ---- */
    const char *list = "# friends\n203.0.113.5\n10.0.0.0/8\n";
    assert(ip_allowed("203.0.113.5", list) == 1);
    assert(ip_allowed("10.5.6.7", list) == 1);
    assert(ip_allowed("8.8.8.8", list) == 0);
    /* inline comment after the address must not break matching */
    const char *list2 = "203.0.113.5  # home office\n";
    assert(ip_allowed("203.0.113.5", list2) == 1);

    /* ---- IPv6 CIDR matching ---- */
    const char *list6 = "2001:db8::/32\n";
    assert(ip_allowed("2001:db8::1", list6) == 1);
    assert(ip_allowed("2001:db8:ffff::abcd", list6) == 1);
    assert(ip_allowed("2001:db9::1", list6) == 0);
    /* family must match: a v4 needle never matches a v6 network and vice versa */
    assert(ip_allowed("10.0.0.1", list6) == 0);
    assert(ip_allowed("2001:db8::1", "10.0.0.0/8\n") == 0);

    /* ---- Robustness: NULL / empty inputs must not crash ---- */
    assert(ip_allowed(NULL, list) == 0);
    assert(ip_allowed("1.2.3.4", NULL) == 0);
    assert(ip_allowed("bogus", list) == 0);
    st_expire(NULL, 0);                              /* no crash */
    st_free(NULL);                                   /* no crash */
    assert(st_count_over_threshold(NULL, 1, NULL, 0) == 0);

    /* ---- Connection-count aggregation (spec 3.2) ---- */
    /* Three connections from .50, two from .60; threshold 3 -> only .50. */
    const char *peers = "9.9.9.50\n9.9.9.50\n9.9.9.50\n9.9.9.60\n9.9.9.60\n";
    char cbuf[256];
    int conns = conn_over_threshold(peers, "", 3, cbuf, sizeof cbuf);
    printf("conn(th=3)=%d buf=[%s]\n", conns, cbuf);
    assert(conns == 1);
    assert(strstr(cbuf, "9.9.9.50") != NULL);
    /* Whitelisted source is excluded even when over threshold. */
    int conns_wl = conn_over_threshold(peers, "9.9.9.50\n", 3, NULL, 0);
    assert(conns_wl == 0);
    /* CIDR whitelist also excludes. */
    assert(conn_over_threshold(peers, "9.9.9.0/24\n", 1, NULL, 0) == 0);
    /* NULL / empty input is safe. */
    assert(conn_over_threshold(NULL, "", 1, NULL, 0) == 0);
    assert(conn_over_threshold("", "", 1, NULL, 0) == 0);
    /* Malformed tokens are skipped, not counted. */
    assert(conn_over_threshold("nonsense\nstill.bad\n", "", 1, NULL, 0) == 0);

    printf("ALL TESTS PASSED\n");
    return 0;
}
