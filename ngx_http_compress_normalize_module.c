#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_flag_t    enable;
    ngx_array_t  *combinations;
} ngx_http_compress_normalize_conf_t;

typedef struct {
    ngx_str_t original_accept_encoding;
} ngx_http_compress_normalize_ctx_t;

static ngx_int_t ngx_http_compress_normalize_handler(ngx_http_request_t *r);
static char *ngx_http_compress_normalize(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_compress_normalize_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_compress_normalize_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_compress_normalize_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_compress_normalize_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_compress_normalize_init(ngx_conf_t *cf);

static ngx_command_t ngx_http_compress_normalize_commands[] = {
    {
        ngx_string("compress_normalize_accept_encoding"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_http_compress_normalize,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_variable_t  ngx_http_compress_normalize_vars[] = {
    { ngx_string("compress_original_accept_encoding"), NULL,
      ngx_http_compress_normalize_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_http_module_t ngx_http_compress_normalize_module_ctx = {
    ngx_http_compress_normalize_add_variables,  /* preconfiguration */
    ngx_http_compress_normalize_init,           /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_compress_normalize_create_loc_conf, /* create location config */
    ngx_http_compress_normalize_merge_loc_conf   /* merge location config */
};

ngx_module_t ngx_http_compress_normalize_module = {
    NGX_MODULE_V1,
    &ngx_http_compress_normalize_module_ctx, /* module context */
    ngx_http_compress_normalize_commands,    /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_compress_normalize_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_compress_normalize_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_compress_normalize_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_compress_normalize_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_compress_normalize_conf_t *prev = parent;
    ngx_http_compress_normalize_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (conf->combinations == NULL) {
        conf->combinations = prev->combinations;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_compress_normalize(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_compress_normalize_conf_t *cncf = conf;

    ngx_str_t        *value;
    ngx_uint_t        i;

    if (cncf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        cncf->enable = 0;
        return NGX_CONF_OK;
    }

    cncf->enable = 1;

    cncf->combinations = ngx_array_create(cf->pool, cf->args->nelts - 1, sizeof(ngx_str_t));
    if (cncf->combinations == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *str = ngx_array_push(cncf->combinations);
        if (str == NULL) {
            return NGX_CONF_ERROR;
        }

        *str = value[i];
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_compress_normalize_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_compress_normalize_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_compress_normalize_module);

    if (ctx == NULL || ctx->original_accept_encoding.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->original_accept_encoding.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->original_accept_encoding.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_compress_normalize_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_compress_normalize_vars; v->name.len; v++) {
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
ngx_http_compress_normalize_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_compress_normalize_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_compress_normalize_handler(ngx_http_request_t *r)
{
    ngx_http_compress_normalize_conf_t  *cncf;
    ngx_http_compress_normalize_ctx_t   *ctx;
    ngx_table_elt_t                     *h;
    ngx_uint_t                           i, j, k;
    ngx_array_t                         *encoding_parts;
    ngx_array_t                         *accepted_encodings;
    ngx_array_t                         *combo_parts;
    ngx_str_t                           *part;
    ngx_str_t                           ae;
    ngx_str_t                           normalized_accept_encoding = ngx_null_string;

    cncf = ngx_http_get_module_loc_conf(r, ngx_http_compress_normalize_module);

    if (!cncf->enable) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_compress_normalize_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_compress_normalize_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_compress_normalize_module);
    }

    h = r->headers_in.accept_encoding;

    if (h == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "no accept-encoding header found, skipping normalization");
        return NGX_DECLINED;
    }

    /* 保存原始的 Accept-Encoding 请求头 */
    ctx->original_accept_encoding.len = h->value.len;
    ctx->original_accept_encoding.data = ngx_pnalloc(r->pool, h->value.len);
    if (ctx->original_accept_encoding.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(ctx->original_accept_encoding.data, h->value.data, h->value.len);

    /* 将 Accept-Encoding 转换为小写并去除空白字符 */
    ae.len = h->value.len;
    ae.data = ngx_pnalloc(r->pool, ae.len);
    if (ae.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(ae.data, h->value.data, ae.len);

    for (i = 0; i < ae.len; i++) {
        ae.data[i] = ngx_tolower(ae.data[i]);
    }

    /* 去除两端的空白字符 */
    while (ae.len > 0 && (ae.data[0] == ' ' || ae.data[0] == '\t')) {
        ae.data++;
        ae.len--;
    }
    while (ae.len > 0 && (ae.data[ae.len - 1] == ' ' || ae.data[ae.len - 1] == '\t')) {
        ae.len--;
    }

    if (ae.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "normalize_accept_encoding: accept-encoding header is empty after trimming, skipping modification");
        return NGX_DECLINED;
    }

    /* 分割 Accept-Encoding */
    encoding_parts = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
    if (encoding_parts == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u_char *p = ae.data;
    u_char *last = ae.data + ae.len;
    u_char *start = p;

    while (p < last) {
        if (*p == ',') {
            u_char *end = p;
            while (start < end && (*start == ' ' || *start == '\t')) {
                start++;
            }
            while (end > start && (*(end - 1) == ' ' || *(end - 1) == '\t')) {
                end--;
            }

            if (start < end) {
                part = ngx_array_push(encoding_parts);
                if (part == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                part->len = end - start;
                part->data = start;
            }

            p++;
            start = p;
        } else {
            p++;
        }
    }

    /* 处理最后一个部分 */
    u_char *end = p;
    while (start < end && (*start == ' ' || *start == '\t')) {
        start++;
    }
    while (end > start && (*(end - 1) == ' ' || *(end - 1) == '\t')) {
        end--;
    }

    if (start < end) {
        part = ngx_array_push(encoding_parts);
        if (part == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        part->len = end - start;
        part->data = start;
    }

    /* 解析编码和 q 值 */
    accepted_encodings = ngx_array_create(r->pool, encoding_parts->nelts, sizeof(ngx_str_t));
    if (accepted_encodings == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_t *enc_parts = encoding_parts->elts;
    for (i = 0; i < encoding_parts->nelts; i++) {
        ngx_str_t enc_part = enc_parts[i];
        u_char *semicolon = ngx_strlchr(enc_part.data, enc_part.data + enc_part.len, ';');
        ngx_str_t encoding;
        ngx_str_t params;
        if (semicolon) {
            encoding.data = enc_part.data;
            encoding.len = semicolon - enc_part.data;

            params.data = semicolon + 1;
            params.len = (enc_part.data + enc_part.len) - params.data;
        } else {
            encoding = enc_part;
            params.data = NULL;
            params.len = 0;
        }

        /* 去除编码两端的空白 */
        while (encoding.len > 0 && (encoding.data[0] == ' ' || encoding.data[0] == '\t')) {
            encoding.data++;
            encoding.len--;
        }
        while (encoding.len > 0 && (encoding.data[encoding.len - 1] == ' ' || encoding.data[encoding.len - 1] == '\t')) {
            encoding.len--;
        }

        if (encoding.len == 0) {
            continue;
        }

        /* 默认 q 值为 1 */
        double q_value = 1.0;

        if (params.len > 0) {
            u_char *param_p = params.data;
            u_char *param_last = params.data + params.len;
            while (param_p < param_last) {
                while (param_p < param_last && (*param_p == ' ' || *param_p == '\t' || *param_p == ';')) {
                    param_p++;
                }

                u_char *param_start = param_p;

                while (param_p < param_last && *param_p != ';') {
                    param_p++;
                }

                u_char *param_end = param_p;

                if (param_end - param_start >= 2 && param_start[0] == 'q' && param_start[1] == '=') {
                    u_char *q_value_str = param_start + 2;
                    size_t q_value_len = param_end - q_value_str;

                    q_value = ngx_atofp(q_value_str, q_value_len, 3);
                    if (q_value == NGX_ERROR) {
                        q_value = 1.0;
                    } else {
                        q_value = q_value / 1000.0;
                    }
                }

                if (param_p < param_last && *param_p == ';') {
                    param_p++;
                }
            }
        }

        if (q_value > 0) {
            ngx_str_t *accepted_enc = ngx_array_push(accepted_encodings);
            if (accepted_enc == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            accepted_enc->len = encoding.len;
            accepted_enc->data = ngx_pnalloc(r->pool, encoding.len);
            if (accepted_enc->data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_memcpy(accepted_enc->data, encoding.data, encoding.len);
        }
    }

    /* 遍历配置的组合 */
    ngx_str_t *combination = cncf->combinations->elts;
    ngx_uint_t combinations_nelts = cncf->combinations->nelts;

    for (j = 0; j < combinations_nelts; j++) {
        ngx_str_t combo = combination[j];

        if (combo.len == 0) {
            continue;
        }

        /* 处理组合字符串 */
        ngx_str_t combo_trimmed;
        combo_trimmed.data = ngx_pnalloc(r->pool, combo.len);
        if (combo_trimmed.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(combo_trimmed.data, combo.data, combo.len);
        combo_trimmed.len = combo.len;

        for (i = 0; i < combo_trimmed.len; i++) {
            combo_trimmed.data[i] = ngx_tolower(combo_trimmed.data[i]);
        }

        while (combo_trimmed.len > 0 && (combo_trimmed.data[0] == ' ' || combo_trimmed.data[0] == '\t')) {
            combo_trimmed.data++;
            combo_trimmed.len--;
        }
        while (combo_trimmed.len > 0 && (combo_trimmed.data[combo_trimmed.len - 1] == ' ' || combo_trimmed.data[combo_trimmed.len - 1] == '\t')) {
            combo_trimmed.len--;
        }

        if (combo_trimmed.len == 0) {
            continue;
        }

        /* 分割组合 */
        combo_parts = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
        if (combo_parts == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        p = combo_trimmed.data;
        last = combo_trimmed.data + combo_trimmed.len;
        start = p;

        while (p < last) {
            if (*p == ',') {
                u_char *end = p;
                while (start < end && (*start == ' ' || *start == '\t')) {
                    start++;
                }
                while (end > start && (*(end - 1) == ' ' || *(end - 1) == '\t')) {
                    end--;
                }

                if (start < end) {
                    part = ngx_array_push(combo_parts);
                    if (part == NULL) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }
                    part->len = end - start;
                    part->data = start;
                }

                p++;
                start = p;
            } else {
                p++;
            }
        }

        end = p;
        while (start < end && (*start == ' ' || *start == '\t')) {
            start++;
        }
        while (end > start && (*(end - 1) == ' ' || *(end - 1) == '\t')) {
            end--;
        }

        if (start < end) {
            part = ngx_array_push(combo_parts);
            if (part == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            part->len = end - start;
            part->data = start;
        }

        /* 检查组合中的编码是否都在接受的编码中 */
        ngx_uint_t all_included = 1;
        ngx_str_t *combo_encodings = combo_parts->elts;
        ngx_uint_t combo_encodings_nelts = combo_parts->nelts;

        for (k = 0; k < combo_encodings_nelts; k++) {
            ngx_str_t combo_encoding = combo_encodings[k];
            ngx_uint_t found = 0;
            ngx_str_t *accepted_encs = accepted_encodings->elts;
            for (i = 0; i < accepted_encodings->nelts; i++) {
                ngx_str_t accepted_encoding = accepted_encs[i];

                if (accepted_encoding.len == combo_encoding.len &&
                    ngx_strncmp(accepted_encoding.data, combo_encoding.data, accepted_encoding.len) == 0) {
                    found = 1;
                    break;
                }
            }

            if (!found) {
                all_included = 0;
                break;
            }
        }

        if (all_included) {
            normalized_accept_encoding.len = combo.len;
            normalized_accept_encoding.data = combo.data;
            break;
        }
    }

    if (normalized_accept_encoding.len > 0) {
        h->value.len = normalized_accept_encoding.len;
        h->value.data = normalized_accept_encoding.data;
    }

    return NGX_DECLINED;
}
