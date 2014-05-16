
/*
 * Copyright (C) 2007 Brice Figureau
 * shm_zone and rbtree code Copyright (c) 2002-2007 Igor Sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define TIMER_FREQUENCY 15 * 1000

typedef enum {
    uploadprogress_state_starting = 0,
    uploadprogress_state_error = 1, 
    uploadprogress_state_done = 2, 
    uploadprogress_state_uploading = 3, 
    uploadprogress_state_none
} ngx_http_uploadprogress_state_t; 

typedef struct {
    ngx_str_t                           name;
    ngx_http_uploadprogress_state_t     idx;
} ngx_http_uploadprogress_state_map_t;

typedef struct ngx_http_uploadprogress_node_s ngx_http_uploadprogress_node_t;

struct ngx_http_uploadprogress_node_s {
    ngx_rbtree_node_t                node;
    ngx_uint_t                       err_status;
    off_t                            rest;
    off_t                            length;
    ngx_uint_t                       done;
    time_t                           timeout;
    struct ngx_http_uploadprogress_node_s *prev;
    struct ngx_http_uploadprogress_node_s *next;
    u_char                           len;
    u_char                           data[1];
};

typedef struct {
    ngx_shm_zone_t                  *shm_zone;
    ngx_rbtree_node_t               *node;
    ngx_http_request_t              *r;
    time_t                           timeout;
} ngx_http_uploadprogress_cleanup_t;

typedef struct {
    ngx_rbtree_t                    *rbtree;
    ngx_http_uploadprogress_node_t   list_head;
    ngx_http_uploadprogress_node_t   list_tail;
} ngx_http_uploadprogress_ctx_t;

typedef struct {
    ngx_array_t                     *values;
    ngx_array_t                     *lengths;
} ngx_http_uploadprogress_template_t;

typedef struct {
    ngx_shm_zone_t                  *shm_zone;
    time_t                           timeout;
    ngx_event_t                      cleanup;
    ngx_http_handler_pt              handler;
    u_char                           track;
    ngx_str_t                        content_type;
    ngx_array_t                      templates;
    ngx_str_t                        header;
    ngx_str_t                        jsonp_parameter;
} ngx_http_uploadprogress_conf_t;

typedef struct {
    ngx_http_event_handler_pt        read_event_handler;
} ngx_http_uploadprogress_module_ctx_t;

static ngx_int_t ngx_http_reportuploads_handler(ngx_http_request_t *r);
static void ngx_http_uploadprogress_cleanup(void *data);
static char *ngx_http_report_uploads(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
static ngx_int_t ngx_http_uploadprogress_init_zone(ngx_shm_zone_t * shm_zone, void *data);
static ngx_int_t ngx_http_uploadprogress_init(ngx_conf_t * cf);
static void *ngx_http_uploadprogress_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_uploadprogress_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_uploadprogress_init_variables_and_templates(ngx_conf_t *cf);

static ngx_int_t ngx_http_uploadprogress_received_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_uploadprogress_offset_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_uploadprogress_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_uploadprogress_callback_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static char* ngx_http_upload_progress_set_template(ngx_conf_t * cf, ngx_http_uploadprogress_template_t *t, ngx_str_t *source);
static char *ngx_http_track_uploads(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
static char *ngx_http_report_uploads(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
static char *ngx_http_upload_progress(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
static char* ngx_http_upload_progress_template(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
static char* ngx_http_upload_progress_java_output(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
static char* ngx_http_upload_progress_json_output(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
static char* ngx_http_upload_progress_jsonp_output(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
static void ngx_clean_old_connections(ngx_event_t * ev);
static ngx_int_t ngx_http_uploadprogress_content_handler(ngx_http_request_t *r);

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_command_t ngx_http_uploadprogress_commands[] = {

    {ngx_string("upload_progress"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2,
     ngx_http_upload_progress,
     0,
     0,
     NULL},

    {ngx_string("track_uploads"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
     ngx_http_track_uploads,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("report_uploads"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_http_report_uploads,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("upload_progress_content_type"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_uploadprogress_conf_t, content_type),
     NULL},

    {ngx_string("upload_progress_template"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
     ngx_http_upload_progress_template,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_uploadprogress_conf_t, templates),
     NULL},

    {ngx_string("upload_progress_java_output"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_http_upload_progress_java_output,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("upload_progress_json_output"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_http_upload_progress_json_output,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("upload_progress_jsonp_output"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_http_upload_progress_jsonp_output,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("upload_progress_header"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_uploadprogress_conf_t, header),
     NULL},

    {ngx_string("upload_progress_jsonp_parameter"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_uploadprogress_conf_t, jsonp_parameter),
     NULL},

    ngx_null_command
};

static ngx_http_variable_t  ngx_http_uploadprogress_variables[] = {

    { ngx_string("uploadprogress_received"), NULL, ngx_http_uploadprogress_received_variable,
      (uintptr_t) offsetof(ngx_http_uploadprogress_node_t, rest),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("uploadprogress_remaining"), NULL, ngx_http_uploadprogress_offset_variable,
      (uintptr_t) offsetof(ngx_http_uploadprogress_node_t, rest),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("uploadprogress_length"), NULL, ngx_http_uploadprogress_offset_variable,
      (uintptr_t) offsetof(ngx_http_uploadprogress_node_t, length),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("uploadprogress_status"), NULL, ngx_http_uploadprogress_status_variable,
      (uintptr_t) offsetof(ngx_http_uploadprogress_node_t, err_status),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("uploadprogress_callback"), NULL, ngx_http_uploadprogress_callback_variable,
      (uintptr_t) NULL,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_http_module_t         ngx_http_uploadprogress_module_ctx = {
    ngx_http_uploadprogress_init_variables_and_templates,      /* preconfiguration */
    ngx_http_uploadprogress_init,       /* postconfiguration */

    NULL,                       /* create main configuration */
    NULL,                       /* init main configuration */

    NULL,                       /* create server configuration */
    NULL,                       /* merge server configuration */

    ngx_http_uploadprogress_create_loc_conf,    /* create location configuration */
    ngx_http_uploadprogress_merge_loc_conf      /* merge location configuration */
};


ngx_module_t                     ngx_http_uploadprogress_module = {
    NGX_MODULE_V1,
    &ngx_http_uploadprogress_module_ctx,        /* module context */
    ngx_http_uploadprogress_commands,   /* module directives */
    NGX_HTTP_MODULE,            /* module type */
    NULL,                       /* init master */
    NULL,                       /* init module */
    NULL,                       /* init process */
    NULL,                       /* init thread */
    NULL,                       /* exit thread */
    NULL,                       /* exit process */
    NULL,                       /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_uploadprogress_state_map_t ngx_http_uploadprogress_state_map[] = {
    {ngx_string("starting"),  uploadprogress_state_starting},
    {ngx_string("error"),     uploadprogress_state_error},
    {ngx_string("done"),      uploadprogress_state_done},
    {ngx_string("uploading"), uploadprogress_state_uploading},
    {ngx_null_string,         uploadprogress_state_none},
};

static ngx_str_t ngx_http_uploadprogress_java_defaults[] = {
    ngx_string("new Object({ 'state' : 'starting' })\r\n"),
    ngx_string("new Object({ 'state' : 'error', 'status' : $uploadprogress_status })\r\n"),
    ngx_string("new Object({ 'state' : 'done' })\r\n"),
    ngx_string("new Object({ 'state' : 'uploading', 'received' : $uploadprogress_received, 'size' : $uploadprogress_length })\r\n")
};

static ngx_str_t ngx_http_uploadprogress_json_defaults[] = {
    ngx_string("{ \"state\" : \"starting\" }\r\n"),
    ngx_string("{ \"state\" : \"error\", \"status\" : $uploadprogress_status }\r\n"),
    ngx_string("{ \"state\" : \"done\" }\r\n"),
    ngx_string("{ \"state\" : \"uploading\", \"received\" : $uploadprogress_received, \"size\" : $uploadprogress_length }\r\n")
};

static ngx_str_t ngx_http_uploadprogress_jsonp_defaults[] = {
    ngx_string("$uploadprogress_callback({ \"state\" : \"starting\" });\r\n"),
    ngx_string("$uploadprogress_callback({ \"state\" : \"error\", \"status\" : $uploadprogress_status });\r\n"),
    ngx_string("$uploadprogress_callback({ \"state\" : \"done\" });\r\n"),
    ngx_string("$uploadprogress_callback({ \"state\" : \"uploading\", \"received\" : $uploadprogress_received, \"size\" : $uploadprogress_length });\r\n")
};


static ngx_array_t ngx_http_uploadprogress_global_templates;

static ngx_str_t*
get_tracking_id(ngx_http_request_t * r)
{
    u_char                          *p, *start_p;
    ngx_uint_t                       i;
    ngx_list_part_t                 *part;
    ngx_table_elt_t                 *header;
    ngx_str_t                       *ret, args;
    ngx_http_uploadprogress_conf_t  *upcf;

    upcf = ngx_http_get_module_loc_conf(r, ngx_http_uploadprogress_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "upload-progress: get_tracking_id");

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].key.len == upcf->header.len
            && ngx_strncasecmp(header[i].key.data, upcf->header.data,
                           header[i].key.len) == 0) {
            ret = ngx_calloc(sizeof(ngx_str_t), r->connection->log );
            ret->data = header[i].value.data;
            ret->len = header[i].value.len;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                            "upload-progress: get_tracking_id found header: %V", ret);
            return ret;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                    "upload-progress: get_tracking_id no header found");

    /* not found, check as a request arg */
    /* it is possible the request args have not been yet created (or already released) */
    /* so let's try harder first from the request line */
    args.len =  r->args.len;
    args.data = r->args.data;
    
    if (args.len && args.data) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                       "upload-progress: get_tracking_id no header found, args found");
        i = 0;
        p = args.data;
        do {
            ngx_uint_t len = args.len - (p - args.data);
            if (len >= (upcf->header.len + 1) && ngx_strncasecmp(p, upcf->header.data, upcf->header.len) == 0
                && p[upcf->header.len] == '=') {
              ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                             "upload-progress: get_tracking_id found args: %s",p);
                i = 1;
                break;
            }
            if (len<=0)
                break;
        } 
        while(p++);

        if (i) {
            start_p = p += upcf->header.len + 1;
            while (p < args.data + args.len) {
                if (*((p++) + 1) == '&') {
                    break;
                }
            }

            ret = ngx_calloc(sizeof(ngx_str_t), r->connection->log);
            ret->data = start_p;
            ret->len = p - start_p;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                           "upload-progress: get_tracking_id found args: %V",ret);
            return ret;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                   "upload-progress: get_tracking_id no id found");
    return NULL;
}

static ngx_http_uploadprogress_node_t *
find_node(ngx_str_t * id, ngx_http_uploadprogress_ctx_t * ctx, ngx_log_t * log)
{
    uint32_t                         hash;
    ngx_rbtree_node_t               *node, *sentinel;
    ngx_int_t                        rc;
    ngx_http_uploadprogress_node_t  *up;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "upload-progress: find_node %V", id);

    hash = ngx_crc32_short(id->data, id->len);

    node = ctx->rbtree->root;
    sentinel = ctx->rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        do {
            up = (ngx_http_uploadprogress_node_t *) node;

            rc = ngx_memn2cmp(id->data, up->data, id->len, (size_t) up->len);

            if (rc == 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                               "upload-progress: found node");
                return up;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && hash == node->key);

        /* found a key with unmatching hash (and value), let's keep comparing hashes then */
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "upload-progress: can't find node");
    return NULL;
}

static void ngx_http_uploadprogress_event_handler(ngx_http_request_t *r);

static ngx_int_t
ngx_http_uploadprogress_content_handler(ngx_http_request_t *r)
{
    ngx_int_t                                    rc;
    ngx_http_uploadprogress_module_ctx_t        *ctx;
    ngx_http_uploadprogress_conf_t              *upcf;
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "upload-progress: ngx_http_uploadprogress_content_handler");
    upcf = ngx_http_get_module_loc_conf(r, ngx_http_uploadprogress_module);

    /* call the original request handler */
    rc = upcf->handler(r);

    /* bail out if error */
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
      return rc;
    }
    
    /* request is OK, hijack the read_event_handler if the request has to be tracked*/
    ctx = ngx_http_get_module_ctx(r, ngx_http_uploadprogress_module);
    if (ctx != NULL) {
        ctx->read_event_handler = r->read_event_handler;
        r->read_event_handler = ngx_http_uploadprogress_event_handler;
    }
    return rc;
}

static ngx_str_t* ngx_http_uploadprogress_strdup(ngx_str_t *src,  ngx_log_t * log)
{
    ngx_str_t *dst;
    dst = ngx_alloc(src->len + sizeof(ngx_str_t), log);
    if (dst == NULL) {
        return NULL;
    }

    dst->len = src->len;
    ngx_memcpy(((char*)dst + sizeof(ngx_str_t)) , src->data, src->len);
    dst->data = ((u_char*)dst + sizeof(ngx_str_t));
    return dst;
}

static void ngx_http_uploadprogress_strdupfree(ngx_str_t *str)
{
    ngx_free(str);
}

static void ngx_http_uploadprogress_event_handler(ngx_http_request_t *r)
{
    ngx_str_t                                   *id, *oldid;
    ngx_slab_pool_t                             *shpool;
    ngx_shm_zone_t                              *shm_zone;
    ngx_http_uploadprogress_ctx_t               *ctx;
    ngx_http_uploadprogress_node_t              *up;
    ngx_http_uploadprogress_conf_t              *upcf;
    ngx_http_uploadprogress_module_ctx_t        *module_ctx;
    size_t                                       size;
    off_t                                        rest;
    

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "upload-progress: ngx_http_uploadprogress_event_handler");
    
    /* find node, update rest */
    oldid = id = get_tracking_id(r);

    if (id == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "upload-progress: read_event_handler cant find id");
        return;
    }

    /* perform a deep copy of id */
    id = ngx_http_uploadprogress_strdup(id, r->connection->log);
    ngx_free(oldid);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upload-progress: read_event_handler found id: %V", id);
    upcf = ngx_http_get_module_loc_conf(r, ngx_http_uploadprogress_module);
    shm_zone = upcf->shm_zone;
    
    /* call the original read event handler */
    module_ctx = ngx_http_get_module_ctx(r, ngx_http_uploadprogress_module);
    if (module_ctx != NULL ) {
        module_ctx->read_event_handler(r);
    }

    /* at this stage, r is not anymore safe to use */
    /* the request could have been closed/freed behind our back */
    /* and thats the same issue with any other material that was allocated in the request pool */
    /* that's why we duplicate id afterward */

    /* it's also possible that the id was null if we got a spurious (like abort) read */
    /* event. In this case we still have called the original read event handler */
    /* but we have to bail out, because we won't ever be able to find our upload node */


    if (shm_zone == NULL) {
        ngx_http_uploadprogress_strdupfree(id);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "upload-progress: read_event_handler no shm_zone for id: %V", id);
        return;
    }

    ctx = shm_zone->data;

    /* get the original connection of the upload */
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    up = find_node(id, ctx, ngx_cycle->log);
    if (up != NULL && !up->done) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "upload-progress: read_event_handler found node: %V", id);
        rest = r->request_body->rest;
        size = r->request_body->buf->last - r->request_body->buf->pos;
        if ((off_t) size < rest) {
            rest -= size;
        } else {
            rest = 0;
        }
        
        up->rest = rest;
        if(up->length == 0)
            up->length = r->headers_in.content_length_n;
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "upload-progress: read_event_handler storing rest %uO/%uO for %V", up->rest, up->length, id);
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "upload-progress: read_event_handler not found: %V", id);
    }
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_http_uploadprogress_strdupfree(id);
}

/* This generates the response for the report */
static ngx_int_t
ngx_http_reportuploads_handler(ngx_http_request_t * r)
{
    ngx_str_t                       *id, response;
    ngx_buf_t                       *b;
    ngx_chain_t                      out;
    ngx_int_t                        rc, found=0, done=0, err_status=0;
    off_t                            rest=0, length=0;
    ngx_uint_t                       len, i;
    ngx_slab_pool_t                 *shpool;
    ngx_http_uploadprogress_conf_t  *upcf;
    ngx_http_uploadprogress_ctx_t   *ctx;
    ngx_http_uploadprogress_node_t  *up;
    ngx_table_elt_t                 *expires, *cc, **ccp;
    ngx_http_uploadprogress_state_t  state;
    ngx_http_uploadprogress_template_t  *t;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    /* get the tracking id if any */
    id = get_tracking_id(r);


    if (id == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "reportuploads handler cant find id");
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "reportuploads handler found id: %V", id);

    upcf = ngx_http_get_module_loc_conf(r, ngx_http_uploadprogress_module);

    if (upcf->shm_zone == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "reportuploads no shm_zone for id: %V", id);
        ngx_free(id);
        return NGX_DECLINED;
    }

    ctx = upcf->shm_zone->data;

    /* get the original connection of the upload */
    shpool = (ngx_slab_pool_t *) upcf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    up = find_node(id, ctx, r->connection->log);
    if (up != NULL) {
        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "reportuploads found node: %V (rest: %uO, length: %uO, done: %ui, err_status: %ui)", id, up->rest, up->length, up->done, up->err_status);
        rest = up->rest;
        length = up->length;
        done = up->done;
        err_status = up->err_status;
        found = 1;
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "reportuploads not found: %V", id);
    }
    ngx_shmtx_unlock(&shpool->mutex);
	ngx_free(id);

    /* send the output */
    r->headers_out.content_type = upcf->content_type;

    /* force no-cache */
    expires = r->headers_out.expires;

    if (expires == NULL) {

        expires = ngx_list_push(&r->headers_out.headers);
        if (expires == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.expires = expires;

        expires->hash = 1;
        expires->key.len = sizeof("Expires") - 1;
        expires->key.data = (u_char *) "Expires";
    }

    len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT");
    expires->value.len = len - 1;

    ccp = r->headers_out.cache_control.elts;
    if (ccp == NULL) {

        if (ngx_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(ngx_table_elt_t *))
            != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ccp = ngx_array_push(&r->headers_out.cache_control);
        if (ccp == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cc = ngx_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cc->hash = 1;
        cc->key.len = sizeof("Cache-Control") - 1;
        cc->key.data = (u_char *) "Cache-Control";

        *ccp = cc;

    } else {
        for (i = 1; i < r->headers_out.cache_control.nelts; i++) {
            ccp[i]->hash = 0;
        }

        cc = ccp[0];
    }

    expires->value.data = (u_char *) "Thu, 01 Jan 1970 00:00:01 GMT";

    cc->value.len = sizeof("no-cache") - 1;
    cc->value.data = (u_char *) "no-cache";


    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    ngx_http_set_ctx(r, up, ngx_http_uploadprogress_module);

/*
 There are 4 possibilities
   * request not yet started: found = false
   * request in error:        err_status >= NGX_HTTP_BAD_REQUEST
   * request finished:        done = true
   * request not yet started but registered:        length==0 && rest ==0
   * reauest in progress:     rest > 0 
 */

    if (!found) {
        state = uploadprogress_state_starting;
    } else if (err_status >= NGX_HTTP_BAD_REQUEST) {
        state = uploadprogress_state_error;
    } else if (done) {
        state = uploadprogress_state_done;
    } else if ( length == 0 && rest == 0 ) {
        state = uploadprogress_state_starting;
    } else {
        state = uploadprogress_state_uploading;
    }

    t = upcf->templates.elts;

    if (ngx_http_script_run(r, &response, t[(ngx_uint_t)state].lengths->elts, 0,
        t[(ngx_uint_t)state].values->elts) == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "upload progress: state=%d, err_status=%ui, remaining=%uO, length=%uO",
        state, err_status, (length - rest), length);

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = b->start = response.data;
    b->last = b->end = response.data + response.len;

    b->temporary = 1;
    b->memory = 1;

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

/* 
Let's register the upload connection in our connections rb-tree
*/
static ngx_int_t
ngx_http_uploadprogress_handler(ngx_http_request_t * r)
{
    size_t                           n;
    ngx_str_t                       *id;
    uint32_t                         hash;
    ngx_slab_pool_t                 *shpool;
    ngx_rbtree_node_t               *node;
    ngx_http_uploadprogress_conf_t  *upcf;
    ngx_http_uploadprogress_ctx_t   *ctx;
    ngx_http_uploadprogress_node_t  *up;
    ngx_http_uploadprogress_cleanup_t *upcln;
    ngx_pool_cleanup_t              *cln;

    /* Is it a POST connection */
    if (r->method != NGX_HTTP_POST) {
        return NGX_DECLINED;
    }

    id = get_tracking_id(r);
    if (id == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trackuploads no id found in POST upload req");
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "trackuploads id found: %V", id);

    upcf = ngx_http_get_module_loc_conf(r, ngx_http_uploadprogress_module);

    if (!upcf->track) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trackuploads not tracking in this location for id: %V", id);
        ngx_free(id);
        return NGX_DECLINED;
    }

    if (upcf->shm_zone == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trackuploads no shm_zone for id: %V", id);
        ngx_free(id);
        return NGX_DECLINED;
    }

    ctx = upcf->shm_zone->data;

    hash = ngx_crc32_short(id->data, id->len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "trackuploads hash %08XD for id: %V", hash, id);

    shpool = (ngx_slab_pool_t *) upcf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    if (find_node(id, ctx, r->connection->log) != NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        /* already found a node with matching progress ID */
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "upload_progress: tracking already registered id: %V", id);

        ngx_free(id);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_uploadprogress_cleanup_t));
    if (cln == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_free(id);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    n = sizeof(ngx_http_uploadprogress_node_t)
        + id->len;

    node = ngx_slab_alloc_locked(shpool, n);
    if (node == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_free(id);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    up = (ngx_http_uploadprogress_node_t *) node;

    node->key = hash;
    up->len = (u_char) id->len;
    up->err_status = r->err_status;
    up->done = 0;
    up->rest = 0;
    up->length = 0;
    up->timeout = 0;

    /* Properly handles small files where no read events happen after the */
    /* request is first handled (apparently this can happen on linux with epoll) */
    if (r->headers_in.content_length_n) {
        up->length = r->headers_in.content_length_n;
        if (r->request_body) {
            up->rest = r->request_body->rest;
        }
    }

    up->next = ctx->list_head.next;
    up->next->prev = up;
    up->prev = &ctx->list_head;
    ctx->list_head.next = up;

    ngx_memcpy(up->data, id->data, id->len);

    ngx_rbtree_insert(ctx->rbtree, node);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "trackuploads: %08XD inserted in rbtree", node->key);

    if (!upcf->cleanup.timer_set) {
        upcf->cleanup.data = upcf->shm_zone;
        upcf->cleanup.handler = ngx_clean_old_connections;
        upcf->cleanup.log = upcf->shm_zone->shm.log;
        ngx_add_timer(&upcf->cleanup, TIMER_FREQUENCY);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    cln->handler = ngx_http_uploadprogress_cleanup;
    upcln = cln->data;

    upcln->shm_zone = upcf->shm_zone;
    upcln->node = node;
    upcln->timeout = upcf->timeout;
    upcln->r = r;

    ngx_free(id);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_uploadprogress_module_ctx_t));
    if (ctx == NULL) {
      return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_uploadprogress_module);

    /* finally says to the core we don't handle anything */
    return NGX_DECLINED;
}

static void
ngx_http_uploadprogress_rbtree_insert_value(ngx_rbtree_node_t * temp,
                                            ngx_rbtree_node_t * node,
                                            ngx_rbtree_node_t * sentinel)
{
    ngx_http_uploadprogress_node_t  *upn, *upnt;

    for (;;) {

        if (node->key < temp->key) {

            if (temp->left == sentinel) {
                temp->left = node;
                break;
            }

            temp = temp->left;

        } else if (node->key > temp->key) {

            if (temp->right == sentinel) {
                temp->right = node;
                break;
            }

            temp = temp->right;

        } else {                /* node->key == temp->key */

            upn = (ngx_http_uploadprogress_node_t *) node;
            upnt = (ngx_http_uploadprogress_node_t *) temp;

            if (ngx_memn2cmp(upn->data, upnt->data, upn->len, upnt->len) < 0) {

                if (temp->left == sentinel) {
                    temp->left = node;
                    break;
                }

                temp = temp->left;

            } else {

                if (temp->right == sentinel) {
                    temp->right = node;
                    break;
                }

                temp = temp->right;
            }
        }
    }

    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static void
ngx_clean_old_connections(ngx_event_t * ev)
{
    ngx_shm_zone_t                  *shm_zone;
    ngx_http_uploadprogress_ctx_t   *ctx;
    ngx_slab_pool_t                 *shpool;
    ngx_rbtree_node_t               *node;
    ngx_http_uploadprogress_node_t  *up, *upprev;
    time_t                           now = ngx_time();
    int                              count = 0;


    /* scan the rbtree */
    shm_zone = ev->data;
    ctx = shm_zone->data;
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
                   "uploadprogress clean old connections at %T", now);

    ngx_shmtx_lock(&shpool->mutex);
    node = (ngx_rbtree_node_t *) ctx->list_tail.prev;
    for (;;) {


        if (node == &ctx->list_head.node) {
            break;
        }

        up = (ngx_http_uploadprogress_node_t *) node;
        upprev = up->prev;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
                       "uploadprogress clean: scanning %08XD (req done %ui) timeout at %T",
                       node->key, up->done, up->timeout);

        if ( (up->done && up->timeout < now) || (ngx_quit || ngx_terminate || ngx_exiting) ) {
            up->next->prev = up->prev;
            up->prev->next = up->next;

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
                           "uploadprogress clean: removing %08XD (req %ui) ",
                           node->key, up->done, up->timeout);

            ngx_rbtree_delete(ctx->rbtree, node);
            ngx_slab_free_locked(shpool, node);
        }
        else
            count++;
        node = (ngx_rbtree_node_t *) upprev;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
               "uploadprogress clean old connections: quit: %ui term: %ui count: %ui", ngx_quit, ngx_terminate, count);

    /* don't reschedule timer if ngx_quit or ngx_terminate && nodes emtpy */
    if ( count > 0 || !(ngx_quit || ngx_terminate || ngx_exiting)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
                   "uploadprogress clean old connections restarting timer");
        ngx_add_timer(ev, TIMER_FREQUENCY);       /* trigger again in 60s */
    } else if (ngx_quit || ngx_terminate || ngx_exiting) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
                   "uploadprogress clean old connections quitting , no more active connections: not restarting timer");
    }
    ngx_shmtx_unlock(&shpool->mutex);
}



/*
removes the expired node from the upload rbtree
*/
static void
ngx_http_uploadprogress_cleanup(void *data)
{
    ngx_http_uploadprogress_cleanup_t *upcln = data;
    ngx_slab_pool_t                 *shpool;
    ngx_rbtree_node_t               *node;
    ngx_http_uploadprogress_node_t  *up;
    ngx_http_request_t              *r;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, upcln->shm_zone->shm.log, 0,
                   "uploadprogress cleanup called");

    shpool = (ngx_slab_pool_t *) upcln->shm_zone->shm.addr;
    node = upcln->node;
    r = upcln->r;
    up = (ngx_http_uploadprogress_node_t *) node;

    ngx_shmtx_lock(&shpool->mutex);
    
    up->done = 1;               /* mark the original request as done */
    up->timeout = ngx_time() + upcln->timeout;      /* keep tracking for 60s */
    
    if (r != NULL ) {
        ngx_uint_t rc = r->err_status ? r->err_status : r->headers_out.status;
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            up->err_status = rc;
        }
    }
    
    ngx_shmtx_unlock(&shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, upcln->shm_zone->shm.log, 0,
                   "uploadprogress cleanup: connection %08XD to be deleted at %T",
                   node->key, up->timeout);

}

static ngx_int_t
ngx_http_uploadprogress_init_zone(ngx_shm_zone_t * shm_zone, void *data)
{
    ngx_http_uploadprogress_ctx_t   *octx = data;

    ngx_slab_pool_t                 *shpool;
    ngx_rbtree_node_t               *sentinel;
    ngx_http_uploadprogress_ctx_t   *ctx;

    ctx = shm_zone->data;

    if (octx) {
        ctx->rbtree = octx->rbtree;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_sentinel_init(sentinel);

    ctx->rbtree->root = sentinel;
    ctx->rbtree->sentinel = sentinel;
    ctx->rbtree->insert = ngx_http_uploadprogress_rbtree_insert_value;

    return NGX_OK;
}

static ngx_int_t
ngx_http_uploadprogress_errortracker(ngx_http_request_t * r)
{
    size_t                           n;
    ngx_str_t                       *id;
    ngx_slab_pool_t                 *shpool;
    ngx_rbtree_node_t               *node;
    ngx_http_uploadprogress_ctx_t   *ctx;
    ngx_http_uploadprogress_node_t  *up;
    ngx_http_uploadprogress_conf_t  *upcf;
    uint32_t                         hash;
    ngx_http_uploadprogress_cleanup_t *upcln;
    ngx_pool_cleanup_t              *cln;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uploadprogress error-tracker error: %D", r->err_status);
    if (r->err_status >= NGX_HTTP_SPECIAL_RESPONSE) {

        upcf = ngx_http_get_module_loc_conf(r, ngx_http_uploadprogress_module);

        if (!upcf->track) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "uploadprogress error-tracker not tracking in this location");
            goto finish;
        }

        id = get_tracking_id(r);
        if (id == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "trackuploads error-tracker no id found in POST upload req");
            goto finish;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trackuploads error-tracker id found: %V", id);


        if (upcf->shm_zone == NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "trackuploads no shm_zone for id: %V", id);
            ngx_free(id);
            goto finish;
        }

        ctx = upcf->shm_zone->data;

        hash = ngx_crc32_short(id->data, id->len);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trackuploads error-tracking hash %08XD for id: %V", hash,
                       id);

        shpool = (ngx_slab_pool_t *) upcf->shm_zone->shm.addr;

        ngx_shmtx_lock(&shpool->mutex);

        if ((up = find_node(id, ctx, r->connection->log)) != NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "trackuploads error-tracking found node for id: %V", id);
            up->err_status = r->err_status;
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_free(id);
            goto finish;
        }

        /* no lz found for this tracking id */
        n = sizeof(ngx_http_uploadprogress_node_t) + id->len;

        cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_uploadprogress_cleanup_t));
        if (cln == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_free(id);
            goto finish;
        }


        node = ngx_slab_alloc_locked(shpool, n);
        if (node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_free(id);							 
            goto finish;
        }

        up = (ngx_http_uploadprogress_node_t *) node;

        node->key = hash;
        up->len = (u_char) id->len;
        up->err_status = r->err_status;
        up->done = 0;
        up->rest = 0;
        up->length = 0;
        up->timeout = 0;

        ngx_memcpy(up->data, id->data, id->len);

        up->next = ctx->list_head.next;
        up->next->prev = up;
        up->prev = &ctx->list_head;
        ctx->list_head.next = up;

        ngx_rbtree_insert(ctx->rbtree, node);

        /* start the timer if needed */
        if (!upcf->cleanup.timer_set) {
            upcf->cleanup.data = upcf->shm_zone;
            upcf->cleanup.handler = ngx_clean_old_connections;
            upcf->cleanup.log = upcf->shm_zone->shm.log;
            ngx_add_timer(&upcf->cleanup, TIMER_FREQUENCY);
        }

        ngx_shmtx_unlock(&shpool->mutex);

        cln->handler = ngx_http_uploadprogress_cleanup;
        upcln = cln->data;
        upcln->shm_zone = upcf->shm_zone;
        upcln->node = node;
        upcln->timeout = upcf->timeout;
        upcln->r = r;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trackuploads error-tracking adding: %08XD", node->key);
        ngx_free(id);
    }

  finish:
    /* call the filter chain as usual */
    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_uploadprogress_init(ngx_conf_t * cf)
{
    ngx_http_handler_pt             *h;
    ngx_http_core_main_conf_t       *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* install the tracking handler */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_uploadprogress_handler;

    /* 
       we also need to track HTTP errors 
       unfortunately, the above handler is not called in case of 
       errors.
       we have to register a header output filter that will be
       called in any case to track those errors
     */
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_uploadprogress_errortracker;

    return NGX_OK;
}

static void*
ngx_http_uploadprogress_create_loc_conf(ngx_conf_t * cf)
{
    ngx_http_uploadprogress_conf_t  *conf;
    ngx_uint_t                            i;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_uploadprogress_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    if(ngx_array_init(&conf->templates, cf->pool, 4, sizeof(ngx_http_uploadprogress_template_t)) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for(i = 0;i < conf->templates.nalloc; i++) {
        ngx_http_uploadprogress_template_t *elt = ngx_array_push(&conf->templates);
        if (elt == NULL) {
            return NGX_CONF_ERROR;
        }
        
        elt->values = NULL;
        elt->lengths = NULL;
    } 

    return conf;
}


static char*
ngx_http_uploadprogress_merge_loc_conf(ngx_conf_t * cf, void *parent, void *child)
{
    ngx_http_uploadprogress_conf_t  *prev = parent;
    ngx_http_uploadprogress_conf_t  *conf = child;
    ngx_http_uploadprogress_template_t   *t, *pt, *gt;
    ngx_uint_t                            i;

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
        conf->timeout = prev->timeout;
        conf->cleanup = prev->cleanup;
        conf->handler = prev->handler;
        conf->track = prev->track;
    }

    ngx_conf_merge_str_value(conf->content_type, prev->content_type, "text/javascript");

    t = conf->templates.elts;
    pt = prev->templates.elts;
    gt = ngx_http_uploadprogress_global_templates.elts;

    for(i = 0;i < conf->templates.nelts; i++) {
        if(t[i].values == NULL) {
            if(pt[i].values == NULL && gt != NULL) {
                t[i].values = gt[i].values;
                t[i].lengths = gt[i].lengths;
            }
            else {
                t[i].values = pt[i].values;
                t[i].lengths = pt[i].lengths;
            }
        }
    } 

    ngx_conf_merge_str_value(conf->header, prev->header, "X-Progress-ID");
    ngx_conf_merge_str_value(conf->jsonp_parameter, prev->jsonp_parameter, "callback");

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_uploadprogress_init_variables_and_templates(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;
    ngx_http_uploadprogress_state_map_t  *m;
    ngx_uint_t                            i;

    /* Add variables */
    for (v = ngx_http_uploadprogress_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    /* Compile global templates (containing Javascript output) */
    if(ngx_array_init(&ngx_http_uploadprogress_global_templates, cf->pool, 4,
        sizeof(ngx_http_uploadprogress_template_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    m = ngx_http_uploadprogress_state_map;
    i = 0;

    while(m->name.data != NULL) {
        ngx_http_uploadprogress_template_t *elt = ngx_array_push(&ngx_http_uploadprogress_global_templates);
        ngx_http_script_variables_count(ngx_http_uploadprogress_jsonp_defaults + i);

        if (ngx_http_upload_progress_set_template(cf, elt, ngx_http_uploadprogress_jsonp_defaults + i) != NGX_CONF_OK) {
            return NGX_ERROR;
        }
        
        m++;
        i++;
    }


    return NGX_OK;
}

static char*
ngx_http_upload_progress(ngx_conf_t * cf, ngx_command_t * cmd, void *conf)
{
    ssize_t                          n;
    ngx_str_t                       *value;
    ngx_shm_zone_t                  *shm_zone;
    ngx_http_uploadprogress_ctx_t   *ctx;

    value = cf->args->elts;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "ngx_upload_progress name: %V", &value[1]);

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_uploadprogress_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->list_head.prev = NULL;
    ctx->list_head.next = &ctx->list_tail;

    ctx->list_tail.prev = &ctx->list_head;
    ctx->list_tail.next = NULL;

    n = ngx_parse_size(&value[2]);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid size of track_uploads \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (n < (ngx_int_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "track_uploads \"%V\" is too small", &value[1]);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &value[1], n,
                                     &ngx_http_uploadprogress_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "ngx_upload_progress name: %V, szhm_zone: %p", &value[1],
                   shm_zone);

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "track_uploads \"%V\" is already created", &value[1]);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_uploadprogress_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}



static char*
ngx_http_track_uploads(ngx_conf_t * cf, ngx_command_t * cmd, void *conf)
{
    ngx_http_core_loc_conf_t        *clcf;
    ngx_http_uploadprogress_conf_t  *lzcf = conf;
    ngx_str_t                       *value;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_track_uploads in");

    value = cf->args->elts;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "ngx_track_uploads name: %V", &value[1]);

    lzcf->shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                           &ngx_http_uploadprogress_module);
    if (lzcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    lzcf->track = (u_char) 1;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "ngx_track_uploads name: %V,szhm_zone: %p", &value[1],
                   lzcf->shm_zone);


    lzcf->timeout = ngx_parse_time(&value[2], 1);
    if (lzcf->timeout == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "track_uploads \"%V\" timeout value invalid", &value[1]);
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    lzcf->handler = clcf->handler;
    if ( lzcf->handler == NULL )
    {
        return "track_upload should be the last directive in the location, after either proxy_pass or fastcgi_pass";
    }
    clcf->handler = ngx_http_uploadprogress_content_handler;
    return NGX_CONF_OK;
}


static char*
ngx_http_report_uploads(ngx_conf_t * cf, ngx_command_t * cmd, void *conf)
{
    ngx_http_uploadprogress_conf_t  *lzcf = conf;
    ngx_http_core_loc_conf_t        *clcf;
    ngx_str_t                       *value;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_report_uploads in");

    value = cf->args->elts;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "ngx_report_uploads name: %V", &value[1]);

    lzcf->shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                           &ngx_http_uploadprogress_module);
    if (lzcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "ngx_report_uploads name: %V, szhm_zone: %p", &value[1],
                   lzcf->shm_zone);

    lzcf->track = (u_char) 0;

    /* install our report handler */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_reportuploads_handler;

    return NGX_CONF_OK;
}

static char*
ngx_http_upload_progress_set_template(ngx_conf_t * cf, ngx_http_uploadprogress_template_t *t, ngx_str_t *source)
{
    ssize_t                               n;
    ngx_http_script_compile_t             sc;

    n = ngx_http_script_variables_count(source);

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

		t->lengths = NULL;
		t->values = NULL;

    sc.cf = cf;
    sc.source = source;
    sc.lengths = &t->lengths;
    sc.values = &t->values;
    sc.variables = n;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char*
ngx_http_upload_progress_template(ngx_conf_t * cf, ngx_command_t * cmd, void *conf)
{
    ngx_http_uploadprogress_conf_t       *upcf = conf;
    ngx_str_t                            *value;
    ngx_http_uploadprogress_state_map_t  *m = ngx_http_uploadprogress_state_map;
    ngx_http_uploadprogress_template_t   *t;

    value = cf->args->elts;

    while(m->name.data != NULL) {
        if((value[1].len == m->name.len && !ngx_strncmp(value[1].data, m->name.data, m->name.len))
           || (value[1].len == 2 && !ngx_strncmp(value[1].data, m->name.data, 2))) {
            break;
        }
        m++;
    }

    if (m->name.data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown state \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    t = (ngx_http_uploadprogress_template_t*)upcf->templates.elts + (ngx_uint_t)m->idx;

    return ngx_http_upload_progress_set_template(cf, t, &value[2]);
}

static char*
ngx_http_upload_progress_java_output(ngx_conf_t * cf, ngx_command_t * cmd, void *conf)
{
    ngx_http_uploadprogress_conf_t       *upcf = conf;
    ngx_http_uploadprogress_template_t   *t;
    ngx_uint_t                            i;
    char*                                 rc;

    t = (ngx_http_uploadprogress_template_t*)upcf->templates.elts;

    for(i = 0;i < upcf->templates.nelts;i++) {
        rc = ngx_http_upload_progress_set_template(cf, t + i, ngx_http_uploadprogress_java_defaults + i);

        if(rc != NGX_CONF_OK) {
            return rc;
        }
    }

    upcf->content_type.data = (u_char*)"text/javascript";
    upcf->content_type.len = sizeof("text/javascript") - 1;

    return NGX_CONF_OK;
}

static char*
ngx_http_upload_progress_json_output(ngx_conf_t * cf, ngx_command_t * cmd, void *conf)
{
    ngx_http_uploadprogress_conf_t       *upcf = conf;
    ngx_http_uploadprogress_template_t   *t;
    ngx_uint_t                            i;
    char*                                 rc;

    t = (ngx_http_uploadprogress_template_t*)upcf->templates.elts;

    for(i = 0;i < upcf->templates.nelts;i++) {
        rc = ngx_http_upload_progress_set_template(cf, t + i, ngx_http_uploadprogress_json_defaults + i);

        if(rc != NGX_CONF_OK) {
            return rc;
        }
    }

    upcf->content_type.data = (u_char*)"application/json";
    upcf->content_type.len = sizeof("application/json") - 1;

    return NGX_CONF_OK;
}

static char*
ngx_http_upload_progress_jsonp_output(ngx_conf_t * cf, ngx_command_t * cmd, void *conf)
{
    ngx_http_uploadprogress_conf_t       *upcf = conf;
    ngx_http_uploadprogress_template_t   *t;
    ngx_uint_t                            i;
    char*                                 rc;

    t = (ngx_http_uploadprogress_template_t*)upcf->templates.elts;

    for(i = 0;i < upcf->templates.nelts;i++) {
        rc = ngx_http_upload_progress_set_template(cf, t + i, ngx_http_uploadprogress_jsonp_defaults + i);

        if(rc != NGX_CONF_OK) {
            return rc;
        }
    }

    upcf->content_type.data = (u_char*)"application/javascript";
    upcf->content_type.len = sizeof("application/javascript") - 1;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_uploadprogress_received_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_uploadprogress_node_t  *up;
    u_char                          *p;
    off_t                           *value;

    up = ngx_http_get_module_ctx(r, ngx_http_uploadprogress_module);

    value = (off_t *) ((char *) up + data);

    p = ngx_palloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%O", up->length - *value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

static ngx_int_t ngx_http_uploadprogress_offset_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_uploadprogress_node_t  *up;
    u_char                          *p;
    off_t                           *value;

    up = ngx_http_get_module_ctx(r, ngx_http_uploadprogress_module);

    value = (off_t *) ((char *) up + data);

    p = ngx_palloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%O", *value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

static ngx_int_t
ngx_http_uploadprogress_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_http_uploadprogress_node_t  *up;
    u_char                          *p;
    off_t                           *value;

    up = ngx_http_get_module_ctx(r, ngx_http_uploadprogress_module);

    value = (off_t *) ((char *) up + data);

    p = ngx_palloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%O", *value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

static ngx_int_t
ngx_http_uploadprogress_callback_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    u_char                          *p, *start_p, *val, prefix[1024];
    ngx_http_uploadprogress_conf_t  *upcf;
    u_int                            len;

    upcf = ngx_http_get_module_loc_conf(r, ngx_http_uploadprogress_module);

    if (r->args.len) {
        /* '=' has to be appended to avoid matching parameters that have the */
        /* configured name as a prefix but are longer */
        ngx_snprintf(prefix, sizeof(prefix) - 1, "%s=", upcf->jsonp_parameter.data);
        len = upcf->jsonp_parameter.len + 1;
        prefix[len] = '\0'; /* Force termination of string */

        p = (u_char *) ngx_strstr(r->args.data, prefix);

        if (p) {
            p += len;
            start_p = p;
            while (p < r->args.data + r->args.len) {
                if (*((p++) + 1) == '&') {
                    break;
                }
            }

            v->len = p - start_p;

            val = ngx_palloc(r->pool, v->len + 1);
            if (val == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(val, start_p, v->len);
            val[v->len] = '\0';

            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = val;
        } else {
            return NGX_ERROR;
        }
    } else {
        return NGX_ERROR;
    }

    return NGX_OK;
}


