#include "simple_gmsm/tlcp.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/*  Application data: write / read / shutdown                         */
/* ------------------------------------------------------------------ */

int tlcp_write(tlcp_conn_t *conn, const unsigned char *data,
               unsigned long len) {
    if (conn->state != TLCP_STATE_ESTABLISHED)
        return -1;

    const unsigned char *p = data;
    unsigned long remaining = len;

    while (remaining > 0) {
        unsigned long chunk = remaining;
        if (chunk > TLCP_MAX_FRAGMENT_LEN)
            chunk = TLCP_MAX_FRAGMENT_LEN;

        int rc = tlcp_record_write(conn, TLCP_CONTENT_APPLICATION_DATA,
                                   p, chunk);
        if (rc != 0)
            return -1;

        p += chunk;
        remaining -= chunk;
    }

    return (int)len;
}

int tlcp_read(tlcp_conn_t *conn, unsigned char *buf, unsigned long buflen) {
    if (conn->state != TLCP_STATE_ESTABLISHED)
        return -1;

    unsigned char ct;
    unsigned long rlen = 0;
    unsigned char tmp[TLCP_MAX_RECORD_LEN + 256];

    if (tlcp_record_read(conn, &ct, tmp, &rlen) != 0)
        return -1;

    if (ct == TLCP_CONTENT_APPLICATION_DATA) {
        if (rlen > buflen)
            rlen = buflen;
        memcpy(buf, tmp, rlen);
        return (int)rlen;
    }

    if (ct == TLCP_CONTENT_ALERT) {
        if (rlen >= 2) {
            conn->last_alert_level = tmp[0];
            conn->last_alert_desc = tmp[1];

            if (tmp[0] == TLCP_ALERT_FATAL || tmp[1] == TLCP_ALERT_CLOSE_NOTIFY) {
                conn->state = TLCP_STATE_ERROR;
                return -1;
            }
        }
        /* Warning alert – try reading again (non-recursive; return 0) */
        return 0;
    }

    /* Unexpected content type */
    return -1;
}

int tlcp_shutdown(tlcp_conn_t *conn) {
    if (conn->state == TLCP_STATE_ERROR)
        return -1;

    int rc = tlcp_send_alert(conn, TLCP_ALERT_WARNING,
                             TLCP_ALERT_CLOSE_NOTIFY);
    conn->state = TLCP_STATE_ERROR;  /* connection no longer usable */
    return rc;
}
