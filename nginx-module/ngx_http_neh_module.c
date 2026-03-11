#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_NEH_DEFAULT_BUCKETS 256
#define NGX_HTTP_NEH_DEFAULT_SHM_SIZE (1 * 1024 * 1024)
#define NGX_HTTP_NEH_MAX_HOST_LEN 128
#define NGX_HTTP_NEH_MAX_TOKEN_LEN 32
#define NGX_HTTP_NEH_KNOCK_URI 0
#define NGX_HTTP_NEH_KNOCK_PORT 1

typedef struct {
    ngx_queue_t queue;
    uint32_t hash;
    ngx_uint_t step;
    ngx_uint_t failures;
    time_t last_seen;
    time_t grant_until;
    time_t blocked_until;
    u_char addr[64];
    size_t addr_len;
    u_char host[NGX_HTTP_NEH_MAX_HOST_LEN];
    size_t host_len;
    u_char token[NGX_HTTP_NEH_MAX_TOKEN_LEN];
    size_t token_len;
} ngx_http_neh_state_t;

typedef struct {
    ngx_queue_t entries;
} ngx_http_neh_bucket_t;

typedef struct {
    ngx_slab_pool_t *shpool;
    ngx_http_neh_bucket_t *buckets;
    ngx_uint_t bucket_count;
} ngx_http_neh_shctx_t;

typedef struct {
    ngx_shm_zone_t *shm_zone;
    ngx_http_neh_shctx_t *sh;
} ngx_http_neh_main_conf_t;

typedef struct {
    ngx_flag_t enable;
    ngx_array_t *sequence;
    ngx_array_t *port_sequence;
    ngx_str_t protected_uri;
    ngx_str_t honeypot_uri;
    ngx_str_t cookie_name;
    ngx_str_t random_secret;
    ngx_str_t path_prefix;
    ngx_msec_t timeout;
    ngx_msec_t access_window;
    ngx_msec_t block_duration;
    ngx_uint_t knock_type;
    ngx_flag_t bind_host;
    ngx_flag_t randomize_sequence;
    ngx_uint_t block_threshold;
    ngx_uint_t sequence_count;
} ngx_http_neh_loc_conf_t;

typedef struct {
    ngx_str_t event;
    ngx_str_t decision;
    ngx_str_t note;
    ngx_int_t step;
} ngx_http_neh_request_ctx_t;

static ngx_int_t ngx_http_neh_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_neh_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_neh_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_neh_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_neh_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_neh_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_http_neh_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_neh_variable_event(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_neh_variable_decision(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_neh_variable_step(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_neh_variable_note(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static char *ngx_http_neh_set_knock_type(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_uint_t ngx_http_neh_sequence_count(ngx_http_neh_loc_conf_t *nlcf);
static void ngx_http_neh_hex32(u_char *dst, uint32_t value);
static ngx_int_t ngx_http_neh_get_host(ngx_http_request_t *r, ngx_str_t *host);
static ngx_int_t ngx_http_neh_get_local_port(ngx_http_request_t *r, in_port_t *port);
static ngx_int_t ngx_http_neh_match_step_uri(ngx_http_request_t *r, ngx_http_neh_loc_conf_t *nlcf, ngx_uint_t *matched_step);
static ngx_int_t ngx_http_neh_get_cookie_value(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value);
static void ngx_http_neh_generate_access_token(ngx_http_request_t *r, ngx_http_neh_state_t *state, ngx_str_t *host, time_t now);
static ngx_int_t ngx_http_neh_set_access_cookie(ngx_http_request_t *r, ngx_http_neh_loc_conf_t *nlcf, ngx_http_neh_state_t *state);
static ngx_int_t ngx_http_neh_is_access_allowed(ngx_http_request_t *r, ngx_http_neh_loc_conf_t *nlcf, ngx_http_neh_state_t *state, ngx_str_t *host, time_t now, ngx_http_neh_request_ctx_t *ctx);
static void ngx_http_neh_apply_block(ngx_http_neh_loc_conf_t *nlcf, ngx_http_neh_state_t *state, time_t now, ngx_http_neh_request_ctx_t *ctx);

static ngx_http_module_t ngx_http_neh_module_ctx;

static ngx_command_t ngx_http_neh_commands[] = {
    { ngx_string("neh_enable"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, enable),
      NULL },

    { ngx_string("neh_sequence"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, sequence),
      NULL },

    { ngx_string("neh_port_sequence"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, port_sequence),
      NULL },

    { ngx_string("neh_knock_type"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_neh_set_knock_type,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("neh_knok_type"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_neh_set_knock_type,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("neh_protected_uri"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, protected_uri),
      NULL },

    { ngx_string("neh_honeypot_uri"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, honeypot_uri),
      NULL },

    { ngx_string("neh_timeout"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, timeout),
      NULL },

    { ngx_string("neh_access_window"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, access_window),
      NULL },

    { ngx_string("neh_cookie_name"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, cookie_name),
      NULL },

    { ngx_string("neh_bind_host"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, bind_host),
      NULL },

    { ngx_string("neh_block_threshold"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, block_threshold),
      NULL },

    { ngx_string("neh_block_duration"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, block_duration),
      NULL },

    { ngx_string("neh_randomize_sequence"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, randomize_sequence),
      NULL },

    { ngx_string("neh_random_secret"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, random_secret),
      NULL },

    { ngx_string("neh_sequence_count"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, sequence_count),
      NULL },

    { ngx_string("neh_path_prefix"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_neh_loc_conf_t, path_prefix),
      NULL },

    ngx_null_command
};

static ngx_http_variable_t ngx_http_neh_vars[] = {
    { ngx_string("neh_event"), NULL, ngx_http_neh_variable_event, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("neh_decision"), NULL, ngx_http_neh_variable_decision, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("neh_step"), NULL, ngx_http_neh_variable_step, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("neh_note"), NULL, ngx_http_neh_variable_note, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    ngx_http_null_variable
};

ngx_module_t ngx_http_neh_module = {
    NGX_MODULE_V1,
    &ngx_http_neh_module_ctx,
    ngx_http_neh_commands,
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

static ngx_http_module_t ngx_http_neh_module_ctx = {
    ngx_http_neh_add_variables,
    ngx_http_neh_postconfiguration,
    ngx_http_neh_create_main_conf,
    NULL,
    NULL,
    NULL,
    ngx_http_neh_create_loc_conf,
    ngx_http_neh_merge_loc_conf
};

static ngx_int_t
ngx_http_neh_match_uri(ngx_str_t *a, ngx_str_t *b)
{
    if (a->len != b->len) {
        return NGX_DECLINED;
    }

    return ngx_strncmp(a->data, b->data, a->len) == 0 ? NGX_OK : NGX_DECLINED;
}

static ngx_http_neh_request_ctx_t *
ngx_http_neh_get_ctx(ngx_http_request_t *r)
{
    ngx_http_neh_request_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_neh_module);
    if (ctx != NULL) {
        return ctx;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_neh_request_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->event = (ngx_str_t) ngx_string("none");
    ctx->decision = (ngx_str_t) ngx_string("pass");
    ctx->note = (ngx_str_t) ngx_string("none");
    ctx->step = -1;

    ngx_http_set_ctx(r, ctx, ngx_http_neh_module);
    return ctx;
}

static ngx_http_neh_state_t *
ngx_http_neh_lookup_state(ngx_http_neh_shctx_t *sh, ngx_str_t *addr, uint32_t hash)
{
    ngx_uint_t idx;
    ngx_queue_t *q;
    ngx_http_neh_state_t *state;

    idx = hash % sh->bucket_count;
    for (q = ngx_queue_head(&sh->buckets[idx].entries);
         q != ngx_queue_sentinel(&sh->buckets[idx].entries);
         q = ngx_queue_next(q))
    {
        state = ngx_queue_data(q, ngx_http_neh_state_t, queue);
        if (state->hash == hash &&
            state->addr_len == addr->len &&
            ngx_strncmp(state->addr, addr->data, addr->len) == 0)
        {
            return state;
        }
    }

    return NULL;
}

static ngx_http_neh_state_t *
ngx_http_neh_get_or_create_state(ngx_http_request_t *r, ngx_http_neh_main_conf_t *nmcf, ngx_str_t *addr)
{
    ngx_http_neh_shctx_t *sh;
    ngx_http_neh_state_t *state;
    ngx_uint_t idx;
    uint32_t hash;

    sh = nmcf->sh;
    hash = ngx_crc32_short(addr->data, addr->len);

    ngx_shmtx_lock(&sh->shpool->mutex);

    state = ngx_http_neh_lookup_state(sh, addr, hash);
    if (state != NULL) {
        ngx_shmtx_unlock(&sh->shpool->mutex);
        return state;
    }

    state = ngx_slab_alloc_locked(sh->shpool, sizeof(ngx_http_neh_state_t));
    if (state == NULL) {
        ngx_shmtx_unlock(&sh->shpool->mutex);
        return NULL;
    }

    ngx_memzero(state, sizeof(ngx_http_neh_state_t));
    state->hash = hash;
    state->addr_len = ngx_min(addr->len, sizeof(state->addr) - 1);
    ngx_memcpy(state->addr, addr->data, state->addr_len);
    state->addr[state->addr_len] = '\0';

    idx = hash % sh->bucket_count;
    ngx_queue_insert_head(&sh->buckets[idx].entries, &state->queue);

    ngx_shmtx_unlock(&sh->shpool->mutex);
    return state;
}

static ngx_int_t
ngx_http_neh_get_local_port(ngx_http_request_t *r, in_port_t *port)
{
    if (r->connection->local_sockaddr == NULL) {
        if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK) {
            return NGX_DECLINED;
        }
    }

    if (r->connection->local_sockaddr == NULL) {
        return NGX_DECLINED;
    }

    *port = ngx_inet_get_port(r->connection->local_sockaddr);
    return NGX_OK;
}

static char *
ngx_http_neh_set_knock_type(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_neh_loc_conf_t *nlcf = conf;
    ngx_str_t *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "uri") == 0) {
        nlcf->knock_type = NGX_HTTP_NEH_KNOCK_URI;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "port") == 0) {
        nlcf->knock_type = NGX_HTTP_NEH_KNOCK_PORT;
        return NGX_CONF_OK;
    }

    return "invalid value, expected \"uri\" or \"port\"";
}

static ngx_int_t
ngx_http_neh_get_host(ngx_http_request_t *r, ngx_str_t *host)
{
    if (r->headers_in.host != NULL && r->headers_in.host->value.len > 0) {
        *host = r->headers_in.host->value;
        return NGX_OK;
    }

    if (r->headers_in.server.len > 0) {
        *host = r->headers_in.server;
        return NGX_OK;
    }

    return NGX_DECLINED;
}

static void
ngx_http_neh_hex32(u_char *dst, uint32_t value)
{
    static u_char hex[] = "0123456789abcdef";
    ngx_uint_t i;

    for (i = 0; i < 8; i++) {
        dst[7 - i] = hex[value & 0xf];
        value >>= 4;
    }
}

static ngx_uint_t
ngx_http_neh_sequence_count(ngx_http_neh_loc_conf_t *nlcf)
{
    if (nlcf->knock_type == NGX_HTTP_NEH_KNOCK_PORT &&
        nlcf->port_sequence != NULL && nlcf->port_sequence->nelts > 0)
    {
        return nlcf->port_sequence->nelts;
    }

    if (nlcf->sequence != NULL && nlcf->sequence->nelts > 0) {
        return nlcf->sequence->nelts;
    }

    return nlcf->sequence_count;
}

static ngx_int_t
ngx_http_neh_match_step_uri(ngx_http_request_t *r, ngx_http_neh_loc_conf_t *nlcf, ngx_uint_t *matched_step)
{
    ngx_uint_t i;
    ngx_str_t *items, host;
    u_char seed[512], generated[256];
    u_char *p;
    uint32_t checksum;
    in_port_t port;
    ngx_int_t parsed;

    if (nlcf->knock_type == NGX_HTTP_NEH_KNOCK_PORT) {
        if (nlcf->port_sequence == NULL || nlcf->port_sequence->nelts == 0) {
            return NGX_DECLINED;
        }

        if (ngx_http_neh_get_local_port(r, &port) != NGX_OK) {
            return NGX_DECLINED;
        }

        items = nlcf->port_sequence->elts;
        for (i = 0; i < nlcf->port_sequence->nelts; i++) {
            parsed = ngx_atoi(items[i].data, items[i].len);
            if (parsed == NGX_ERROR) {
                continue;
            }

            if ((in_port_t) parsed == port) {
                *matched_step = i;
                return NGX_OK;
            }
        }

        return NGX_DECLINED;
    }

    if (nlcf->sequence != NULL && nlcf->sequence->nelts > 0) {
        items = nlcf->sequence->elts;
        for (i = 0; i < nlcf->sequence->nelts; i++) {
            if (ngx_http_neh_match_uri(&r->uri, &items[i]) == NGX_OK) {
                *matched_step = i;
                return NGX_OK;
            }
        }

        return NGX_DECLINED;
    }

    if (!nlcf->randomize_sequence || nlcf->random_secret.len == 0 || nlcf->sequence_count == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_neh_get_host(r, &host) != NGX_OK) {
        return NGX_DECLINED;
    }

    for (i = 0; i < nlcf->sequence_count; i++) {
        p = ngx_snprintf(seed, sizeof(seed), "%V|%V|%ui", &nlcf->random_secret, &host, i);
        checksum = ngx_crc32_short(seed, p - seed);

        generated[0] = '/';
        p = ngx_cpymem(generated + 1, nlcf->path_prefix.data, nlcf->path_prefix.len);
        *p++ = '-';
        ngx_http_neh_hex32(p, checksum);
        p += 8;

        if ((size_t) (p - generated) == r->uri.len &&
            ngx_strncmp(generated, r->uri.data, r->uri.len) == 0)
        {
            *matched_step = i;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_neh_get_cookie_value(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value)
{
    ngx_table_elt_t *cookie;
    u_char *start, *end, *eq, *name_end;

    cookie = r->headers_in.cookie;
    if (cookie == NULL || cookie->value.len == 0) {
        return NGX_DECLINED;
    }

    start = cookie->value.data;
    end = start + cookie->value.len;

    while (start < end) {
        while (start < end && (*start == ' ' || *start == ';')) {
            start++;
        }

        eq = start;
        while (eq < end && *eq != '=' && *eq != ';') {
            eq++;
        }

        if (eq >= end || *eq != '=') {
            break;
        }

        name_end = eq;
        while (name_end > start && *(name_end - 1) == ' ') {
            name_end--;
        }

        if ((size_t) (name_end - start) == name->len &&
            ngx_strncasecmp(start, name->data, name->len) == 0)
        {
            eq++;
            value->data = eq;
            while (eq < end && *eq != ';') {
                eq++;
            }
            value->len = eq - value->data;
            return NGX_OK;
        }

        start = eq + 1;
        while (start < end && *start != ';') {
            start++;
        }
    }

    return NGX_DECLINED;
}

static void
ngx_http_neh_generate_access_token(ngx_http_request_t *r, ngx_http_neh_state_t *state, ngx_str_t *host, time_t now)
{
    u_char seed[512], *p;
    uint32_t a, b;

    p = ngx_snprintf(seed, sizeof(seed), "%V|%V|%T|%P|%ui", &r->connection->addr_text, host, now, ngx_pid, state->failures);
    a = ngx_crc32_short(seed, p - seed);

    p = ngx_snprintf(seed, sizeof(seed), "%V|%V|%T|%P|%ui|grant", host, &r->connection->addr_text, now, ngx_pid, state->step);
    b = ngx_crc32_short(seed, p - seed);

    ngx_http_neh_hex32(state->token, a);
    ngx_http_neh_hex32(state->token + 8, b);
    state->token_len = 16;
}

static ngx_int_t
ngx_http_neh_set_access_cookie(ngx_http_request_t *r, ngx_http_neh_loc_conf_t *nlcf, ngx_http_neh_state_t *state)
{
    ngx_table_elt_t *set_cookie;
    u_char *cookie, *p;
    size_t len;

    if (nlcf->cookie_name.len == 0 || state->token_len == 0) {
        return NGX_OK;
    }

    len = nlcf->cookie_name.len + 1 + state->token_len + sizeof("; Max-Age=; Path=/; HttpOnly; SameSite=Strict") - 1 + NGX_INT_T_LEN;
    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(cookie, nlcf->cookie_name.data, nlcf->cookie_name.len);
    *p++ = '=';
    p = ngx_cpymem(p, state->token, state->token_len);
    p = ngx_sprintf(p, "; Max-Age=%ui; Path=/; HttpOnly; SameSite=Strict", (ngx_uint_t) (nlcf->access_window / 1000));

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.data = cookie;
    set_cookie->value.len = p - cookie;

    return NGX_OK;
}

static void
ngx_http_neh_apply_block(ngx_http_neh_loc_conf_t *nlcf, ngx_http_neh_state_t *state, time_t now, ngx_http_neh_request_ctx_t *ctx)
{
    if (nlcf->block_threshold == 0 || nlcf->block_duration == 0) {
        return;
    }

    if (state->failures >= nlcf->block_threshold) {
        state->blocked_until = now + (time_t) (nlcf->block_duration / 1000);
        ctx->event = (ngx_str_t) ngx_string("block_activated");
        ctx->decision = (ngx_str_t) ngx_string("blocked");
        ctx->note = (ngx_str_t) ngx_string("threshold_exceeded");
    }
}

static ngx_int_t
ngx_http_neh_is_access_allowed(ngx_http_request_t *r, ngx_http_neh_loc_conf_t *nlcf, ngx_http_neh_state_t *state, ngx_str_t *host, time_t now, ngx_http_neh_request_ctx_t *ctx)
{
    ngx_str_t cookie;

    if (state->blocked_until > now) {
        ctx->event = (ngx_str_t) ngx_string("request_blocked");
        ctx->decision = (ngx_str_t) ngx_string("blocked");
        ctx->note = (ngx_str_t) ngx_string("ip_blocked");
        return NGX_DECLINED;
    }

    if (state->grant_until < now) {
        ctx->event = (ngx_str_t) ngx_string("protected_denied");
        ctx->decision = (ngx_str_t) ngx_string("honeypot");
        ctx->note = (ngx_str_t) ngx_string("grant_expired");
        return NGX_DECLINED;
    }

    if (nlcf->bind_host &&
        (state->host_len != host->len || ngx_strncmp(state->host, host->data, host->len) != 0))
    {
        ctx->event = (ngx_str_t) ngx_string("protected_denied");
        ctx->decision = (ngx_str_t) ngx_string("blocked");
        ctx->note = (ngx_str_t) ngx_string("host_mismatch");
        return NGX_DECLINED;
    }

    if (nlcf->cookie_name.len > 0) {
        if (ngx_http_neh_get_cookie_value(r, &nlcf->cookie_name, &cookie) != NGX_OK) {
            ctx->event = (ngx_str_t) ngx_string("protected_denied");
            ctx->decision = (ngx_str_t) ngx_string("blocked");
            ctx->note = (ngx_str_t) ngx_string("cookie_missing");
            return NGX_DECLINED;
        }

        if (cookie.len != state->token_len ||
            ngx_strncmp(cookie.data, state->token, state->token_len) != 0)
        {
            ctx->event = (ngx_str_t) ngx_string("protected_denied");
            ctx->decision = (ngx_str_t) ngx_string("blocked");
            ctx->note = (ngx_str_t) ngx_string("cookie_invalid");
            return NGX_DECLINED;
        }
    }

    ctx->event = (ngx_str_t) ngx_string("protected_allowed");
    ctx->decision = (ngx_str_t) ngx_string("pass");
    ctx->note = (ngx_str_t) ngx_string("cookie_valid");
    return NGX_OK;
}

static ngx_int_t
ngx_http_neh_redirect_to_honeypot(ngx_http_request_t *r, ngx_http_neh_request_ctx_t *ctx, ngx_http_neh_loc_conf_t *nlcf)
{
    if (ngx_http_neh_match_uri(&r->uri, &nlcf->honeypot_uri) == NGX_OK) {
        return NGX_DECLINED;
    }

    ctx->event = (ngx_str_t) ngx_string("redirect_honeypot");
    ctx->decision = (ngx_str_t) ngx_string("honeypot");

    return ngx_http_internal_redirect(r, &nlcf->honeypot_uri, &r->args);
}

static ngx_int_t
ngx_http_neh_handler(ngx_http_request_t *r)
{
    ngx_http_neh_loc_conf_t *nlcf;
    ngx_http_neh_main_conf_t *nmcf;
    ngx_http_neh_request_ctx_t *ctx;
    ngx_http_neh_state_t *state;
    ngx_http_neh_shctx_t *sh;
    ngx_str_t addr, host;
    ngx_uint_t matched_step, expected_step, sequence_total;
    time_t now;
    ngx_int_t rc;

    nlcf = ngx_http_get_module_loc_conf(r, ngx_http_neh_module);
    if (!nlcf->enable) {
        return NGX_DECLINED;
    }

    if (r->internal && ngx_http_neh_match_uri(&r->uri, &nlcf->honeypot_uri) == NGX_OK) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_neh_get_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    nmcf = ngx_http_get_module_main_conf(r, ngx_http_neh_module);
    if (nmcf == NULL || nmcf->sh == NULL) {
        return NGX_DECLINED;
    }

    addr = r->connection->addr_text;
    if (addr.len == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_neh_get_host(r, &host) != NGX_OK) {
        return NGX_DECLINED;
    }

    state = ngx_http_neh_get_or_create_state(r, nmcf, &addr);
    if (state == NULL) {
        return NGX_DECLINED;
    }

    sh = nmcf->sh;
    now = ngx_time();

    rc = ngx_http_neh_match_step_uri(r, nlcf, &matched_step);
    sequence_total = ngx_http_neh_sequence_count(nlcf);

    ngx_shmtx_lock(&sh->shpool->mutex);

    if (state->last_seen != 0 &&
        now - state->last_seen > (time_t) (nlcf->timeout / 1000))
    {
        state->step = 0;
    }

    state->last_seen = now;

    if (state->blocked_until > now && rc != NGX_OK) {
        ctx->event = (ngx_str_t) ngx_string("request_blocked");
        ctx->decision = (ngx_str_t) ngx_string("blocked");
        ctx->note = (ngx_str_t) ngx_string("ip_blocked");
        ngx_shmtx_unlock(&sh->shpool->mutex);
        return ngx_http_neh_redirect_to_honeypot(r, ctx, nlcf);
    }

    if (rc == NGX_OK) {
        expected_step = state->step;

        if (matched_step == expected_step) {
            state->step++;
            ctx->step = (ngx_int_t) state->step;
            ctx->note = (ngx_str_t) ngx_string("sequence_ok");

            if (state->step == sequence_total) {
                state->host_len = ngx_min(host.len, sizeof(state->host) - 1);
                ngx_memcpy(state->host, host.data, state->host_len);
                state->host[state->host_len] = '\0';
                ngx_http_neh_generate_access_token(r, state, &host, now);
                state->grant_until = now + (time_t) (nlcf->access_window / 1000);
                state->step = 0;
                state->failures = 0;
                state->blocked_until = 0;
                ctx->event = (ngx_str_t) ngx_string("knock_success");
                ctx->decision = (ngx_str_t) ngx_string("grant_window");
                ctx->note = (ngx_str_t) ngx_string("cookie_issued");
                if (ngx_http_neh_set_access_cookie(r, nlcf, state) != NGX_OK) {
                    ngx_shmtx_unlock(&sh->shpool->mutex);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            } else {
                ctx->event = (ngx_str_t) ngx_string("knock_progress");
                ctx->decision = (ngx_str_t) ngx_string("await_next");
            }

            ngx_shmtx_unlock(&sh->shpool->mutex);
            return NGX_HTTP_NO_CONTENT;
        }

        state->failures++;
        if (matched_step == 0) {
            state->step = 1;
            ctx->event = (ngx_str_t) ngx_string("knock_restart");
            ctx->decision = (ngx_str_t) ngx_string("restart_sequence");
            ctx->note = (ngx_str_t) ngx_string("restart_from_step0");
            ctx->step = 1;
            ngx_shmtx_unlock(&sh->shpool->mutex);
            return NGX_HTTP_NO_CONTENT;
        }

        state->step = 0;
        ctx->event = (ngx_str_t) ngx_string("knock_failed");
        ctx->decision = (ngx_str_t) ngx_string("honeypot");
        ctx->note = (ngx_str_t) ngx_string("wrong_path");
        ngx_http_neh_apply_block(nlcf, state, now, ctx);
        ngx_shmtx_unlock(&sh->shpool->mutex);
        return ngx_http_neh_redirect_to_honeypot(r, ctx, nlcf);
    }

    if (ngx_http_neh_match_uri(&r->uri, &nlcf->protected_uri) == NGX_OK) {
        if (ngx_http_neh_is_access_allowed(r, nlcf, state, &host, now, ctx) == NGX_OK) {
            ngx_shmtx_unlock(&sh->shpool->mutex);
            return NGX_DECLINED;
        }

        state->failures++;
        ngx_http_neh_apply_block(nlcf, state, now, ctx);
        ngx_shmtx_unlock(&sh->shpool->mutex);
        return ngx_http_neh_redirect_to_honeypot(r, ctx, nlcf);
    }

    ngx_shmtx_unlock(&sh->shpool->mutex);
    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_neh_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_neh_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_neh_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_neh_main_conf_t *nmcf;
    ngx_str_t shm_name = ngx_string("neh_shared_state");

    nmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_neh_module);
    nmcf->shm_zone = ngx_shared_memory_add(cf, &shm_name, NGX_HTTP_NEH_DEFAULT_SHM_SIZE, &ngx_http_neh_module);
    if (nmcf->shm_zone == NULL) {
        return NGX_ERROR;
    }

    nmcf->shm_zone->init = ngx_http_neh_init_zone;
    nmcf->shm_zone->data = nmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_neh_handler;
    return NGX_OK;
}

static ngx_int_t
ngx_http_neh_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t *shpool;
    ngx_http_neh_main_conf_t *nmcf;
    ngx_http_neh_main_conf_t *old_nmcf;
    ngx_http_neh_shctx_t *sh;
    ngx_uint_t i;

    nmcf = shm_zone->data;

    if (data) {
        old_nmcf = data;
        nmcf->sh = old_nmcf->sh;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = ngx_slab_alloc(shpool, sizeof(ngx_http_neh_shctx_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    sh->shpool = shpool;
    sh->bucket_count = NGX_HTTP_NEH_DEFAULT_BUCKETS;
    sh->buckets = ngx_slab_alloc(shpool, sizeof(ngx_http_neh_bucket_t) * sh->bucket_count);
    if (sh->buckets == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < sh->bucket_count; i++) {
        ngx_queue_init(&sh->buckets[i].entries);
    }

    nmcf->sh = sh;
    return NGX_OK;
}

static void *
ngx_http_neh_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_neh_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_neh_main_conf_t));
    return conf;
}

static void *
ngx_http_neh_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_neh_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_neh_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->bind_host = NGX_CONF_UNSET;
    conf->randomize_sequence = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->access_window = NGX_CONF_UNSET_MSEC;
    conf->block_duration = NGX_CONF_UNSET_MSEC;
    conf->knock_type = NGX_CONF_UNSET_UINT;
    conf->block_threshold = NGX_CONF_UNSET_UINT;
    conf->sequence_count = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_http_neh_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_neh_loc_conf_t *prev = parent;
    ngx_http_neh_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->bind_host, prev->bind_host, 1);
    ngx_conf_merge_value(conf->randomize_sequence, prev->randomize_sequence, 0);
    ngx_conf_merge_uint_value(conf->knock_type, prev->knock_type, NGX_HTTP_NEH_KNOCK_URI);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 30000);
    ngx_conf_merge_msec_value(conf->access_window, prev->access_window, 60000);
    ngx_conf_merge_msec_value(conf->block_duration, prev->block_duration, 120000);
    ngx_conf_merge_uint_value(conf->block_threshold, prev->block_threshold, 5);
    ngx_conf_merge_uint_value(conf->sequence_count, prev->sequence_count, 3);
    ngx_conf_merge_str_value(conf->protected_uri, prev->protected_uri, "/admin");
    ngx_conf_merge_str_value(conf->honeypot_uri, prev->honeypot_uri, "/__neh_honeypot__");
    ngx_conf_merge_str_value(conf->cookie_name, prev->cookie_name, "neh_access");
    ngx_conf_merge_str_value(conf->path_prefix, prev->path_prefix, "knock");
    ngx_conf_merge_str_value(conf->random_secret, prev->random_secret, "");

    if (conf->sequence == NULL) {
        conf->sequence = prev->sequence;
    }

    if (conf->port_sequence == NULL) {
        conf->port_sequence = prev->port_sequence;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_neh_set_variable_str(ngx_http_variable_value_t *v, ngx_str_t *src)
{
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = src->len;
    v->data = src->data;
    return NGX_OK;
}

static ngx_int_t
ngx_http_neh_variable_event(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_neh_request_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_neh_module);
    if (ctx == NULL) {
        ngx_str_t none = ngx_string("none");
        return ngx_http_neh_set_variable_str(v, &none);
    }

    return ngx_http_neh_set_variable_str(v, &ctx->event);
}

static ngx_int_t
ngx_http_neh_variable_decision(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_neh_request_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_neh_module);
    if (ctx == NULL) {
        ngx_str_t pass = ngx_string("pass");
        return ngx_http_neh_set_variable_str(v, &pass);
    }

    return ngx_http_neh_set_variable_str(v, &ctx->decision);
}

static ngx_int_t
ngx_http_neh_variable_step(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *buf;
    ngx_http_neh_request_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_neh_module);
    if (ctx == NULL || ctx->step < 0) {
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->len = 1;
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    buf = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    v->data = buf;
    v->len = ngx_sprintf(buf, "%i", ctx->step) - buf;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
ngx_http_neh_variable_note(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_neh_request_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_neh_module);
    if (ctx == NULL) {
        ngx_str_t none = ngx_string("none");
        return ngx_http_neh_set_variable_str(v, &none);
    }

    return ngx_http_neh_set_variable_str(v, &ctx->note);
}
