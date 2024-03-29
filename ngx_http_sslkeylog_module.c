/*
 * Andrey Tikhonov <tiacorpo@gmail.com>, 2020-2023
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef ngx_int_t (*ngx_sslkeylog_variable_handler_pt)(ngx_connection_t *c,
    ngx_pool_t *pool, ngx_str_t *s);


static ngx_int_t ngx_http_sslkeylog_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_int_t ngx_http_sslkeylog_add_variables(ngx_conf_t *cf);


static ngx_int_t sslkeylog_get_se(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);
static ngx_int_t sslkeylog_get_cr(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);
static ngx_int_t sslkeylog_get_sr(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);
static ngx_int_t sslkeylog_get_mk(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);
static ngx_int_t sslkeylog_get_cs(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);
static ngx_int_t sslkeylog_get_es(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);
static ngx_int_t sslkeylog_get_ees(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);
static ngx_int_t sslkeylog_get_cets(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);
static ngx_int_t sslkeylog_get_cts(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);
static ngx_int_t sslkeylog_get_sts(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);
static ngx_int_t sslkeylog_get_chts(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);
static ngx_int_t sslkeylog_get_shts(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s);

static ngx_int_t _sslkeylog_copy_str(ngx_connection_t *c, ngx_pool_t *pool, const ngx_str_t *src, ngx_str_t *dst);

static ngx_http_module_t  ngx_http_sslkeylog_module_ctx = {
    ngx_http_sslkeylog_add_variables,      /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_sslkeylog_module = {
    NGX_MODULE_V1,
    &ngx_http_sslkeylog_module_ctx,        /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_sslkeylog_vars[] = {

    { ngx_string("sslkeylog_se"), NULL, ngx_http_sslkeylog_variable, /* session id */
      (uintptr_t) sslkeylog_get_se, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("sslkeylog_cr"), NULL, ngx_http_sslkeylog_variable, /* client random */
      (uintptr_t) sslkeylog_get_cr, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("sslkeylog_sr"), NULL, ngx_http_sslkeylog_variable, /* server random */
      (uintptr_t) sslkeylog_get_sr, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("sslkeylog_mk"), NULL, ngx_http_sslkeylog_variable, /* master key */
      (uintptr_t) sslkeylog_get_mk, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("sslkeylog_cs"), NULL, ngx_http_sslkeylog_variable, /* cipher suite */
      (uintptr_t) sslkeylog_get_cs, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("sslkeylog_es"), NULL, ngx_http_sslkeylog_variable, /* exporter secret */
      (uintptr_t) sslkeylog_get_es, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("sslkeylog_ees"), NULL, ngx_http_sslkeylog_variable, /* early exporter secret */
      (uintptr_t) sslkeylog_get_ees, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("sslkeylog_cets"), NULL, ngx_http_sslkeylog_variable, /* client early traffic secret */
      (uintptr_t) sslkeylog_get_cets, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("sslkeylog_cts"), NULL, ngx_http_sslkeylog_variable, /* client traffic secret */
      (uintptr_t) sslkeylog_get_cts, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("sslkeylog_sts"), NULL, ngx_http_sslkeylog_variable, /* server traffic secret */
      (uintptr_t) sslkeylog_get_sts, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("sslkeylog_chts"), NULL, ngx_http_sslkeylog_variable, /* client handshake traffic secret */
      (uintptr_t) sslkeylog_get_chts, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("sslkeylog_shts"), NULL, ngx_http_sslkeylog_variable, /* server handshake traffic secret */
      (uintptr_t) sslkeylog_get_shts, NGX_HTTP_VAR_CHANGEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
sslkeylog_get_se(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    u_char        *buf;
    SSL_SESSION   *sess;
    unsigned int   len;

    sess = SSL_get0_session(c->ssl->connection);
    if (sess == NULL) {
        s->len = 0;
        return NGX_OK;
    }

    buf = (u_char *) SSL_SESSION_get_id(sess, &len);

    s->len = 2 * len;
    s->data = ngx_pnalloc(pool, 2 * len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(s->data, buf, len);

    return NGX_OK;
}


static ngx_int_t
sslkeylog_get_cs(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    unsigned long cnid;

    cnid = SSL_CIPHER_get_id(SSL_get_current_cipher(c->ssl->connection)) & 0xffffL;

    s->len = 4;
    s->data = ngx_pnalloc(pool, 5); /* there is no way to tell snprintf not to print terminating null */
    if (s->data == NULL) {
        return NGX_ERROR;
    }
    snprintf((char *) s->data, 5, "%04lX", cnid);
    return NGX_OK;
}


static ngx_int_t
sslkeylog_get_cr(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    u_char      *buf;
    size_t      len;

    buf = ngx_pnalloc(pool, SSL3_RANDOM_SIZE);
    len = SSL_get_client_random(c->ssl->connection, buf, SSL3_RANDOM_SIZE);

    s->len = len * 2;
    s->data = ngx_pnalloc(pool, len * 2);
    if (s->data == NULL) {
        return NGX_ERROR;
    }
    ngx_hex_dump(s->data, buf, len);
    return NGX_OK;
}


static ngx_int_t
sslkeylog_get_sr(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    u_char      *buf;
    size_t      len;

    buf = ngx_pnalloc(pool, SSL3_RANDOM_SIZE);
    len = SSL_get_server_random(c->ssl->connection, buf, SSL3_RANDOM_SIZE);

    s->len = len * 2;
    s->data = ngx_pnalloc(pool, len * 2);
    if (s->data == NULL) {
        return NGX_ERROR;
    }
    ngx_hex_dump(s->data, buf, len);
    return NGX_OK;
}


static ngx_int_t
sslkeylog_get_mk(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    SSL_SESSION *sess;
    u_char      *buf;
    size_t      len;

    sess = SSL_get0_session(c->ssl->connection);
    if (sess == NULL) {
        s->len = 0;
        return NGX_OK;
    }

    buf = ngx_pnalloc(pool, SSL_MAX_MASTER_KEY_LENGTH);
    len = SSL_SESSION_get_master_key(sess, buf, SSL_MAX_MASTER_KEY_LENGTH);

    s->len = len * 2;
    s->data = ngx_pnalloc(pool, len * 2);
    if (s->data == NULL) {
        return NGX_ERROR;
    }
    ngx_hex_dump(s->data, buf, len);
    return NGX_OK;
}

static ngx_int_t
_sslkeylog_copy_str(ngx_connection_t *c, ngx_pool_t *pool, const ngx_str_t *src, ngx_str_t *dst)
{
/*
    *** use this variant in case connection pool is destroyed before variable is evaluated and/or used ***
    u_char *buf;

    buf = ngx_pnalloc(pool, dst->len);
    if (buf == NULL) {
      ngx_log_error(NGX_LOG_ERR, c->log, 0, "sslkeylog: ngx_pnalloc() failed");
      return NGX_ERROR;
    }
    ngx_memcpy(buf, src->data, src->len);
    dst->len = src->len;
    dst->data = buf;
*/
    dst->len = src->len;
    dst->data = src->data;
    return NGX_OK;
}

static ngx_int_t
sslkeylog_get_es(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    return _sslkeylog_copy_str(c, pool, &(c->ssl->sslkeylog_es), s);
}

static ngx_int_t
sslkeylog_get_ees(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    return _sslkeylog_copy_str(c, pool, &(c->ssl->sslkeylog_ees), s);
}

static ngx_int_t
sslkeylog_get_cets(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    return _sslkeylog_copy_str(c, pool, &(c->ssl->sslkeylog_cets), s);
}

static ngx_int_t
sslkeylog_get_cts(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    return _sslkeylog_copy_str(c, pool, &(c->ssl->sslkeylog_cts), s);
}

static ngx_int_t
sslkeylog_get_sts(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    return _sslkeylog_copy_str(c, pool, &(c->ssl->sslkeylog_sts), s);
}

static ngx_int_t
sslkeylog_get_chts(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    return _sslkeylog_copy_str(c, pool, &(c->ssl->sslkeylog_chts), s);
}

static ngx_int_t
sslkeylog_get_shts(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    return _sslkeylog_copy_str(c, pool, &(c->ssl->sslkeylog_shts), s);
}

static ngx_int_t
ngx_http_sslkeylog_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sslkeylog_variable_handler_pt  handler = (ngx_sslkeylog_variable_handler_pt) data;

    ngx_str_t  s;

    if (r->connection->ssl) {

        if (handler(r->connection, r->pool, &s) != NGX_OK) {
            return NGX_ERROR;
        }

        v->len = s.len;
        v->data = s.data;

        if (v->len) {
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;

            return NGX_OK;
        }
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_sslkeylog_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_sslkeylog_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
