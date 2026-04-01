#include "simple_gmsm/tlcp.h"

int tlcp_send_alert(tlcp_conn_t* conn, unsigned char level,
                    unsigned char desc) {
    unsigned char alert[2];

    alert[0] = level;
    alert[1] = desc;

    conn->last_alert_level = level;
    conn->last_alert_desc = desc;

    /* On fatal alert, transition to error state */
    if (level == TLCP_ALERT_FATAL)
        conn->state = TLCP_STATE_ERROR;

    return tlcp_record_write(conn, TLCP_CONTENT_ALERT, alert, 2);
}
