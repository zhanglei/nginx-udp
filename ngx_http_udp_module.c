#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define UDP_DEFAULT_PORT 8086

typedef struct ngx_http_udp_op_s ngx_http_udp_op_t;

typedef u_char *(*ngx_http_udp_op_run_pt) (ngx_http_request_t *r, u_char *buf, ngx_http_udp_op_t *op);
typedef size_t (*ngx_http_udp_op_getlen_pt) (ngx_http_request_t *r, uintptr_t data);

struct ngx_http_udp_op_s {
    size_t len;
    ngx_http_udp_op_getlen_pt getlen;
    ngx_http_udp_op_run_pt run;
    uintptr_t data;
};

typedef struct {
    ngx_addr_t peer_addr;
    ngx_udp_connection_t *udp_connection;
    ngx_log_t *log;
} ngx_http_udp_endpoint_t;

typedef struct {
    ngx_array_t *flushes;
    ngx_array_t *ops;
} ngx_http_udp_format_t;

typedef struct {
    int off;
    ngx_http_udp_endpoint_t *endpoint;
    ngx_http_udp_format_t *format;
} ngx_http_udp_main_conf_t;

typedef struct {
    ngx_str_t                   name;
    size_t                      len;
    ngx_http_udp_op_run_pt      run;
} ngx_http_udp_var_t;

ngx_int_t ngx_udp_connect(ngx_udp_connection_t *udpconn);

static ngx_int_t ngx_http_udp_init(ngx_conf_t *cf);
static void *ngx_http_udp_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_udp_set_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_udp_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_udp_compile_format(ngx_conf_t *cf, ngx_array_t *flushes, ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s);
static ngx_int_t ngx_http_udp_variable_compile(ngx_conf_t *cf, ngx_http_udp_op_t *op, ngx_str_t *value);
static size_t ngx_http_udp_variable_getlen(ngx_http_request_t *r, uintptr_t data);
static u_char *ngx_http_udp_variable(ngx_http_request_t *r, u_char *buf, ngx_http_udp_op_t *op);
static uintptr_t ngx_http_udp_escape(u_char *dst, u_char *src, size_t size);

static u_char *ngx_http_udp_sec(ngx_http_request_t *r, u_char *buf, ngx_http_udp_op_t *op);
static u_char *ngx_http_udp_msec(ngx_http_request_t *r, u_char *buf, ngx_http_udp_op_t *op);
static u_char *ngx_http_udp_usec(ngx_http_request_t *r, u_char *buf, ngx_http_udp_op_t *op);

static ngx_http_udp_var_t  ngx_http_udp_vars[] = {
    { ngx_string("udp_sec"), NGX_TIME_T_LEN, ngx_http_udp_sec },
    { ngx_string("udp_msec"), NGX_TIME_T_LEN, ngx_http_udp_msec },
    { ngx_string("udp_usec"), NGX_TIME_T_LEN, ngx_http_udp_usec },
    { ngx_null_string, 0, NULL }
};

static ngx_command_t ngx_http_udp_commands[] = {
    {
        ngx_string("udp_server"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_http_udp_set_server,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL,
    },
    {
        ngx_string("udp_format"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_http_udp_set_format,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL,
    }
};

static ngx_http_module_t ngx_http_udp_module_ctx = {
    NULL,
    ngx_http_udp_init,
    ngx_http_udp_create_main_conf,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};

ngx_module_t ngx_http_udp_module = {
    NGX_MODULE_V1,
    &ngx_http_udp_module_ctx,
    ngx_http_udp_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static void
ngx_http_udp_dummy_handler(ngx_event_t *ev)
{
}

static ngx_int_t
ngx_http_udp_send(ngx_http_udp_endpoint_t *endpoint, u_char *buf, size_t len)
{
    ssize_t                n;
    ngx_udp_connection_t  *udpconn;

    udpconn = endpoint->udp_connection;

    if (udpconn->connection == NULL) {

        udpconn->log = *endpoint->log;
        udpconn->log.handler = NULL;
        udpconn->log.data = NULL;
        udpconn->log.action = "logging";

        if(ngx_udp_connect(udpconn) != NGX_OK) {
            if(udpconn->connection != NULL) {
                ngx_free_connection(udpconn->connection);
                udpconn->connection = NULL;
            }

            return NGX_ERROR;
        }

        udpconn->connection->data = endpoint;
        udpconn->connection->read->handler = ngx_http_udp_dummy_handler;
        udpconn->connection->read->resolver = 0;
    }

    n = ngx_send(udpconn->connection, buf, len);

    if (n == -1) {
        return NGX_ERROR;
    }

    if ((size_t) n != (size_t) len) {
        ngx_log_error(NGX_LOG_CRIT, &udpconn->log, 0, "udp: send incomplete. length: %d, sent: %d", len, n);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_udp_handler(ngx_http_request_t *r)
{
    ngx_http_udp_main_conf_t *mainconf;
    u_char *p, *line;
    size_t len;
    ngx_uint_t i;
    ngx_http_udp_op_t *op;

    mainconf = ngx_http_get_module_main_conf(r, ngx_http_udp_module);
    if (mainconf == NULL || mainconf->off == 1 || mainconf->endpoint == NULL) {
        return NGX_OK;
    }

    ngx_http_udp_format_t *format = mainconf->format;

    ngx_http_script_flush_no_cacheable_variables(r, format->flushes);

    len = 0;
    op = format->ops->elts;
    for (i = 0; i < format->ops->nelts; i++) {
        if (op[i].len == 0) {
            len += op[i].getlen(r, op[i].data);
        } else {
            len += op[i].len;
        }
    }

    line = ngx_pnalloc(r->pool, len);
    if (line == NULL) {
        return NGX_ERROR;
    }
    p = line;

    for (i = 0; i < format->ops->nelts; i++) {
        p = op[i].run(r, p, &op[i]);
    }

    return ngx_http_udp_send(mainconf->endpoint, line, p - line);
}

static void
ngx_udp_endpoint_cleanup(void *data)
{
    ngx_http_udp_endpoint_t *endpoint;
    endpoint = data;

    if (endpoint->udp_connection) {
        if (endpoint->udp_connection->connection) {
            ngx_close_connection(endpoint->udp_connection->connection);
        }
        ngx_free(endpoint->udp_connection);
    }
}

static ngx_int_t
ngx_udp_init_endpoint(ngx_conf_t *cf, ngx_http_udp_endpoint_t *endpoint)
{
    ngx_pool_cleanup_t *cleanup;
    ngx_udp_connection_t *udpconn;

    cleanup = ngx_pool_cleanup_add(cf->pool, 0);
    if (cleanup == NULL) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "udp: failed to add pool cleanup for endpoint");
        return NGX_ERROR;
    }

    cleanup->handler = ngx_udp_endpoint_cleanup;
    cleanup->data = endpoint;

    udpconn = ngx_calloc(sizeof(ngx_udp_connection_t), cf->log);
    if (udpconn == NULL) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "udp: failed to alloc memory for udp connection");
        return NGX_ERROR;
    }

    endpoint->udp_connection = udpconn;

    udpconn->sockaddr = endpoint->peer_addr.sockaddr;
    udpconn->socklen = endpoint->peer_addr.socklen;
    udpconn->server = endpoint->peer_addr.name;

    endpoint->log = &cf->cycle->new_log;

    return NGX_OK;
}

static ngx_int_t
ngx_http_udp_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;

    ngx_http_udp_main_conf_t *mainconf;
    mainconf = ngx_http_conf_get_module_main_conf(cf, ngx_http_udp_module);

    if (mainconf == NULL || mainconf->off == 1 || mainconf->endpoint == NULL) {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0, "udp: module loaded but turned off");
        return NGX_OK;
    }

    if (ngx_udp_init_endpoint(cf, mainconf->endpoint) != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "udp: failed to init endpoint");
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "udp: failed to push handler");
        return NGX_ERROR;
    }
    *h = ngx_http_udp_handler;
    return NGX_OK;
}

static void *
ngx_http_udp_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_udp_main_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_udp_main_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->off = 1;
    conf->endpoint = NULL;
    return conf;
}

static char *
ngx_http_udp_set_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_url_t url;
    ngx_str_t *value;
    ngx_http_udp_main_conf_t *mainconf = conf;
    ngx_http_udp_endpoint_t *endpoint;

    ngx_memzero(&url, sizeof(ngx_url_t));

    value = cf->args->elts;
    url.url = value[1];
    url.default_port = UDP_DEFAULT_PORT;
    url.no_resolve = 0;

    if (ngx_parse_url(cf->pool, &url) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "parse url %V: %s", &url.host, url.err);
        return NGX_CONF_ERROR;
    }

    endpoint = ngx_pcalloc(cf->pool, sizeof(ngx_http_udp_endpoint_t));
    if (endpoint == NULL) {
        return NGX_CONF_ERROR;
    }
    endpoint->peer_addr = url.addrs[0];

    mainconf->endpoint = endpoint;
    mainconf->off = 0;

    return NGX_CONF_OK;
}

static char*
ngx_http_udp_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_udp_main_conf_t *mainconf = conf;
    ngx_http_udp_format_t *format;

    format = ngx_pcalloc(cf->pool, sizeof(ngx_http_udp_format_t));
    if (format == NULL) {
        return NGX_CONF_ERROR;
    }

    format->flushes = ngx_array_create(cf->pool, 4, sizeof(ngx_int_t));
    if (format->flushes == NULL) {
        return NGX_CONF_ERROR;
    }

    format->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_http_udp_op_t));
    if (format->ops== NULL) {
        return NGX_CONF_ERROR;
    }

    mainconf->format = format;

    return ngx_http_udp_compile_format(cf, format->flushes, format->ops, cf->args, 1);
}

static u_char *
ngx_http_udp_copy_short(ngx_http_request_t *r, u_char *buf, ngx_http_udp_op_t *op)
{
    size_t     len;
    uintptr_t  data;

    len = op->len;
    data = op->data;

    while (len--) {
        *buf++ = (u_char) (data & 0xff);
        data >>= 8;
    }

    return buf;
}


static u_char *
ngx_http_udp_copy_long(ngx_http_request_t *r, u_char *buf, ngx_http_udp_op_t *op)
{
    return ngx_cpymem(buf, (u_char *) op->data, op->len);
}

static char*
ngx_http_udp_compile_format(ngx_conf_t *cf, ngx_array_t *flushes, ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s)
{
    u_char *data, *p, ch;
    ngx_http_udp_op_t *op;
    ngx_int_t *flush;
    size_t i, len;
    ngx_str_t var;
    ngx_uint_t bracket;
    ngx_http_udp_var_t *v;

    ngx_str_t *value = args->elts;

    for (; s < args->nelts; s++) {
        i = 0;
        while (i < value[s].len) {
            op = ngx_array_push(ops);
            if (op == NULL) {
                return NGX_CONF_ERROR;
            }

            data = &value[s].data[i];

            if (value[s].data[i] == '$') {

                if (++i == value[s].len) {
                    goto invalid;
                }

                if (value[s].data[i] == '{') {
                    bracket = 1;

                    if (++i == value[s].len) {
                        goto invalid;
                    }

                    var.data = &value[s].data[i];

                } else {
                    bracket = 0;
                    var.data = &value[s].data[i];
                }

                for (var.len = 0; i < value[s].len; i++, var.len++) {
                    ch = value[s].data[i];

                    if (ch == '}' && bracket) {
                        i++;
                        bracket = 0;
                        break;
                    }

                    if ((ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9')
                        || ch == '_')
                    {
                        continue;
                    }

                    break;
                }

                if (bracket) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "the closing bracket in \"%V\" "
                                       "variable is missing", &var);
                    return NGX_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                for (v = ngx_http_udp_vars; v->name.len; v++) {
                    if (v->name.len == var.len && ngx_strncmp(v->name.data, var.data, var.len) == 0) {
                        op->len = v->len;
                        op->getlen = NULL;
                        op->run = v->run;
                        op->data = 0;

                        goto found;
                    }
                }

                if (ngx_http_udp_variable_compile(cf, op, &var) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }

                if (flushes) {

                    flush = ngx_array_push(flushes);
                    if (flush == NULL) {
                        return NGX_CONF_ERROR;
                    }

                    *flush = op->data;
                }

            found:
                continue;
            }

            i++;

            while (i < value[s].len && value[s].data[i] != '$') {
                i++;
            }

            len = &value[s].data[i] - data;

            if (len) {

                op->len = len;
                op->getlen = NULL;

                if (len <= sizeof(uintptr_t)) {
                    op->run = ngx_http_udp_copy_short;
                    op->data = 0;

                    while (len--) {
                        op->data <<= 8;
                        op->data |= data[len];
                    }

                } else {
                    op->run = ngx_http_udp_copy_long;

                    p = ngx_pnalloc(cf->pool, len);
                    if (p == NULL) {
                        return NGX_CONF_ERROR;
                    }

                    ngx_memcpy(p, data, len);
                    op->data = (uintptr_t) p;
                }
            }
        }
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return NGX_CONF_ERROR;
}

static ngx_int_t
ngx_http_udp_variable_compile(ngx_conf_t *cf, ngx_http_udp_op_t *op, ngx_str_t *value)
{
    ngx_int_t  index;

    index = ngx_http_get_variable_index(cf, value);
    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    op->len = 0;
    op->getlen = ngx_http_udp_variable_getlen;
    op->run = ngx_http_udp_variable;
    op->data = index;

    return NGX_OK;
}

static size_t
ngx_http_udp_variable_getlen(ngx_http_request_t *r, uintptr_t data)
{
    uintptr_t                   len;
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, data);

    if (value == NULL || value->not_found) {
        return 1;
    }

    len = ngx_http_udp_escape(NULL, value->data, value->len);

    value->escape = len ? 1 : 0;

    return value->len + len * 3;
}


static u_char *
ngx_http_udp_variable(ngx_http_request_t *r, u_char *buf, ngx_http_udp_op_t *op)
{
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, op->data);

    if (value == NULL || value->not_found) {
        *buf = '-';
        return buf + 1;
    }

    if (value->escape == 0) {
        return ngx_cpymem(buf, value->data, value->len);

    } else {
        return (u_char *) ngx_http_udp_escape(buf, value->data, value->len);
    }
}


static uintptr_t
ngx_http_udp_escape(u_char *dst, u_char *src, size_t size)
{
    ngx_uint_t      n;
    static u_char   hex[] = "0123456789ABCDEF";

    static uint32_t   escape[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000004, /* 0000 0000 0000 0000  0000 0000 0000 0100 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x10000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };


    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n = 0;

        while (size) {
            if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
                n++;
            }
            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {
        if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
            *dst++ = '\\';
            *dst++ = 'x';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }
        size--;
    }

    return (uintptr_t) dst;
}

static u_char *
ngx_http_udp_sec(ngx_http_request_t *r, u_char *buf, ngx_http_udp_op_t *op)
{
    ngx_time_t *tp;

    tp = ngx_timeofday();

    return ngx_sprintf(buf, "%T", tp->sec);
}

static u_char *
ngx_http_udp_msec(ngx_http_request_t *r, u_char *buf, ngx_http_udp_op_t *op)
{
    ngx_time_t *tp;

    tp = ngx_timeofday();

    return ngx_sprintf(buf, "%T%03T", tp->sec, tp->msec);
}

static u_char *
ngx_http_udp_usec(ngx_http_request_t *r, u_char *buf, ngx_http_udp_op_t *op)
{
    struct timeval tv;

    ngx_gettimeofday(&tv);

    return ngx_sprintf(buf, "%T%06T", tv.tv_sec, tv.tv_usec);
}
