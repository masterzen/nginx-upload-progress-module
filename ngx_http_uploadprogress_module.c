
/*
 * Copyright (C) 2007 Brice Figureau
 * shm_zone and rbtree code Copyright (c) 2002-2007 Igor Sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define TIMER_FREQUENCY 15 * 1000

typedef struct ngx_http_uploadprogress_node_s ngx_http_uploadprogress_node_t;

struct ngx_http_uploadprogress_node_s {
    ngx_rbtree_node_t                node;
    ngx_http_request_t              *r;
    ngx_uint_t                       err_status;
    time_t                           timeout;
    struct ngx_http_uploadprogress_node_s *prev;
    struct ngx_http_uploadprogress_node_s *next;
    u_char                           len;
    u_char                           data[1];
};

typedef struct {
    ngx_shm_zone_t                  *shm_zone;
    ngx_rbtree_node_t               *node;
    time_t                           timeout;
} ngx_http_uploadprogress_cleanup_t;

typedef struct {
    ngx_rbtree_t                    *rbtree;
    ngx_http_uploadprogress_node_t   list_head;
    ngx_http_uploadprogress_node_t   list_tail;
} ngx_http_uploadprogress_ctx_t;

typedef struct {
    ngx_shm_zone_t                  *shm_zone;
		time_t                           timeout;
    ngx_event_t                      cleanup;
    u_char                           track;
} ngx_http_uploadprogress_conf_t;

static ngx_int_t ngx_http_reportuploads_handler(ngx_http_request_t *r);
static void ngx_http_uploadprogress_cleanup(void *data);
static char *ngx_http_report_uploads(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
static ngx_int_t ngx_http_uploadprogress_init_zone(ngx_shm_zone_t * shm_zone, void *data);
static ngx_int_t ngx_http_uploadprogress_init(ngx_conf_t * cf);
static void *ngx_http_uploadprogress_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_uploadprogress_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_track_uploads(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
static char *ngx_http_report_uploads(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
static char *ngx_http_upload_progress(ngx_conf_t * cf, ngx_command_t * cmd, void *conf);
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

    ngx_null_command
};


static ngx_http_module_t         ngx_http_uploadprogress_module_ctx = {
    NULL,                       /* preconfiguration */
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

static ngx_str_t x_progress_id = ngx_string("X-Progress-ID");

static ngx_str_t*
get_tracking_id(ngx_http_request_t * r)
{
    u_char                          *p, *start_p;
    ngx_uint_t                       i;
    ngx_list_part_t                 *part;
    ngx_table_elt_t                 *header;
    ngx_str_t                       *ret;

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

        if (header[i].key.len == x_progress_id.len
            && ngx_strncasecmp(header[i].key.data, x_progress_id.data,
                           header[i].key.len) == 0) {
            ret = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
            ret->data = header[i].value.data;
            ret->len = header[i].value.len;
				    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			                     "upload-progress: get_tracking_id found header: %V", ret);
            return ret;
        }
    }

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		               "upload-progress: get_tracking_id no header found");

    /* not found, check as a reaquest arg */
    if (r->args.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                       "upload-progress: get_tracking_id no header found but args present");
        i = 0;
        p = r->args.data;
        do {
            ngx_uint_t len = r->args.len - (p - r->args.data);
            if (len >= 14 && ngx_strncasecmp(p, (u_char*)"X-Progress-ID=", 14) == 0) {
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
            start_p = p += 14;
            while (p < r->args.data + r->args.len) {
                if (*p++ != '&') {
                    continue;
                }
            }

            ret = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
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

        break;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "upload-progress: can't find node");
    return NULL;
}


static ngx_int_t
ngx_http_uploadprogress_content_handler(ngx_http_request_t *r)
{
  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "upload-progress: ngx_http_uploadprogress_content_handler");
	return ngx_http_proxy_handler(r);
}

/* This generates the response for the report */
static ngx_int_t
ngx_http_reportuploads_handler(ngx_http_request_t * r)
{
    ngx_str_t                       *id;
    ngx_buf_t                       *b;
    ngx_chain_t                      out;
    ngx_http_request_t              *orig;
    ngx_int_t                        rc, size;
    ngx_uint_t                       len, i;
    ngx_slab_pool_t                 *shpool;
    ngx_http_uploadprogress_conf_t  *upcf;
    ngx_http_uploadprogress_ctx_t   *ctx;
    ngx_http_uploadprogress_node_t  *up;
    ngx_table_elt_t                 *expires, *cc, **ccp;

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
        return NGX_DECLINED;
    }

    orig = NULL;
    ctx = upcf->shm_zone->data;

    /* get the original connection of the upload */
    shpool = (ngx_slab_pool_t *) upcf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    up = find_node(id, ctx, r->connection->log);
    if (up != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "reportuploads found node: %V", id);
        orig = up->r;
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "reportuploads not found: %V", id);
    }
    ngx_shmtx_unlock(&shpool->mutex);

    /* send the output */
    r->headers_out.content_type.len = sizeof("text/javascript") - 1;
    r->headers_out.content_type.data = (u_char *) "text/javascript";

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

    if (orig == NULL || orig->request_body == NULL) {
        if (up == NULL ) {
            size = sizeof("new Object({ 'state' : 'starting' })\r\n");
        } else if (up != NULL && up->err_status >= NGX_HTTP_SPECIAL_RESPONSE) {
            size = sizeof("new Object({ 'state' : 'error', 'status' : ") + NGX_INT_T_LEN + sizeof(" })\r\n");
        } else {
            size = sizeof("new Object({ 'state' : 'done' })\r\n");
        }
    } else if (orig->err_status == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE) {
        size = sizeof("new Object({ 'state' : 'error', 'status' : 413 })\r\n");
    } else {
        size =
            sizeof("new Object({ 'state' : 'uploading', 'received' : ") +
            NGX_INT_T_LEN + sizeof(" })\r\n");
        size += sizeof(", 'size' : ") + NGX_INT_T_LEN;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    if (orig == NULL || orig->request_body == NULL ) {
        if (up == NULL) {
            b->last = ngx_cpymem(b->last, "new Object({ 'state' : 'starting' })\r\n",
                                 sizeof("new Object({ 'state' : 'starting' })\r\n") -
                                 1);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "reportuploads returning starting");
        } else if (up != NULL && up->err_status >= NGX_HTTP_SPECIAL_RESPONSE) {
            b->last = ngx_cpymem(b->last, "new Object({ 'state' : 'error', 'status' : ",
                                   sizeof("new Object({ 'state' : 'error', 'status' : ") - 1);
        		b->last =	ngx_sprintf(b->last, "%ui })\r\n", up->err_status );
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "reportuploads returning error condition: %ui", up->err_status);
        }
				else {
            b->last = ngx_cpymem(b->last, "new Object({ 'state' : 'done' })\r\n",
                                   sizeof("new Object({ 'state' : 'done' })\r\n") -
                                 1);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "reportuploads returning done");
				}
    } else if (orig->err_status == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE) {
        b->last =
            ngx_cpymem(b->last,
                       "new Object({ 'state' : 'error', 'status' : 413 })\r\n",
                       sizeof
                       ("new Object({ 'state' : 'error', 'status' : 413 })\r\n") -
                       1);
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "reportuploads returning error 413");
    } else {
        b->last =
            ngx_cpymem(b->last, "new Object({ 'state' : 'uploading', 'received' : ",
                         sizeof("new Object({ 'state' : 'uploading', 'received' : ") -
                       1);

        b->last =
            ngx_sprintf(b->last, "%uO, 'size' : %uO })\r\n",
                        (orig->headers_in.content_length_n -
                         orig->request_body->rest),
                        orig->headers_in.content_length_n);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "reportuploads returning %uO / %uO",
                       (orig->headers_in.content_length_n -
                        orig->request_body->rest),
                       orig->headers_in.content_length_n);

    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);;
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
        return NGX_DECLINED;
    }

    if (upcf->shm_zone == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trackuploads no shm_zone for id: %V", id);
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

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_uploadprogress_cleanup_t));
    if (cln == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    n = sizeof(ngx_http_uploadprogress_node_t)
        + id->len;

    node = ngx_slab_alloc_locked(shpool, n);
    if (node == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    up = (ngx_http_uploadprogress_node_t *) node;

    node->key = hash;
    up->len = (u_char) id->len;
    up->r = r;
    up->err_status = r->err_status;

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

    /* start the timer if needed */

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
    ngx_http_uploadprogress_node_t  *up;
    time_t                           now = ngx_time();


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

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
                       "uploadprogress clean: scanning %08XD (req %p) timeout at %T",
                       node->key, up->r, up->timeout);

        if (up->r == NULL && up->timeout < now) {
            up->next->prev = up->prev;
            up->prev->next = up->next;

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
                           "uploadprogress clean: removing %08XD (req %p) ",
                           node->key, up->r, up->timeout);

            ngx_rbtree_delete(ctx->rbtree, node);
            ngx_slab_free_locked(shpool, node);
        }

        node = (ngx_rbtree_node_t *) up->prev;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
                   "uploadprogress clean old connections restarting timer");

    ngx_add_timer(ev, TIMER_FREQUENCY);       /* trigger again in 60s */

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
    ngx_http_uploadprogress_ctx_t   *ctx;
    ngx_http_uploadprogress_node_t  *up;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, upcln->shm_zone->shm.log, 0,
                   "uploadprogress cleanup called");

    ctx = upcln->shm_zone->data;
    shpool = (ngx_slab_pool_t *) upcln->shm_zone->shm.addr;
    node = upcln->node;
    up = (ngx_http_uploadprogress_node_t *) node;

    up->r = NULL;               /* mark the original request as done */
    up->timeout = ngx_time() + upcln->timeout;      /* keep tracking for 60s */

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
            up->r = NULL;       /* don't really track it since it errors */
            up->err_status = r->err_status;
            ngx_shmtx_unlock(&shpool->mutex);
            goto finish;
        }

        /* no lz found for this tracking id */
        n = sizeof(ngx_http_uploadprogress_node_t) + id->len;

        cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_uploadprogress_cleanup_t));
        if (cln == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            goto finish;
        }


        node = ngx_slab_alloc_locked(shpool, n);
        if (node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            goto finish;
        }

        up = (ngx_http_uploadprogress_node_t *) node;

        node->key = hash;
        up->len = (u_char) id->len;
        up->r = NULL;           /* don't really track it since it errors */
        up->err_status = r->err_status;
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

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trackuploads error-tracking adding: %08XD", node->key);
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

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_uploadprogress_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    return conf;
}


static char*
ngx_http_uploadprogress_merge_loc_conf(ngx_conf_t * cf, void *parent, void *child)
{
    ngx_http_uploadprogress_conf_t  *prev = parent;
    ngx_http_uploadprogress_conf_t  *conf = child;

    if (conf->shm_zone == NULL) {
        *conf = *prev;
    }

    return NGX_CONF_OK;
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
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

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

    if (lzcf->timeout == NGX_PARSE_LARGE_TIME) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "track_uploads \"%V\" timeout value must be less than 68 years", &value[1]);
        return NGX_CONF_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_uploadprogress_content_handler;
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
