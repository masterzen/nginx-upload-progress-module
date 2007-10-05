
/*
 * Copyright (C) 2007 Brice Figureau
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    u_char              color;
 		ngx_http_request_t *r;
    u_char              len;
    u_char              data[1];
} ngx_http_uploadprogress_node_t;


typedef struct {
    ngx_shm_zone_t     *shm_zone;
    ngx_rbtree_node_t  *node;
} ngx_http_uploadprogress_cleanup_t;

typedef struct {
    ngx_rbtree_t       *rbtree;
} ngx_http_uploadprogress_ctx_t;

typedef struct {
    ngx_shm_zone_t     *shm_zone;
		u_char							track;
} ngx_http_uploadprogress_conf_t;

static ngx_int_t ngx_http_reportuploads_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_reportuploads_handler(ngx_http_request_t *r);
static void ngx_http_uploadprogress_cleanup(void *data);
static char *ngx_http_report_uploads(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_uploadprogress_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_http_uploadprogress_init(ngx_conf_t *cf);
static void *ngx_http_uploadprogress_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_uploadprogress_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_track_uploads(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_report_uploads(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_upload_progress(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_uploadprogress_commands[] = {

  { ngx_string("upload_progress"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
    ngx_http_upload_progress,
    0,
    0,
    NULL },

  { ngx_string("track_uploads"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_http_track_uploads,
	  NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

  { ngx_string("report_uploads"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_report_uploads,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

		ngx_null_command
};


static ngx_http_module_t  ngx_http_uploadprogress_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_uploadprogress_init,  /* postconfiguration */

    NULL,  /* create main configuration */
    NULL,    /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_uploadprogress_create_loc_conf,          /* create location configuration */
    ngx_http_uploadprogress_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_uploadprogress_module = {
    NGX_MODULE_V1,
    &ngx_http_uploadprogress_module_ctx,      /* module context */
    ngx_http_uploadprogress_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_str_t x_progress_id = ngx_string("X-Progress-ID");

static ngx_str_t*
get_tracking_id(ngx_http_request_t *r)
{
	u_char										 *p,*start_p;
	ngx_uint_t i;
  ngx_list_part_t              *part;
  ngx_table_elt_t              *header;
	ngx_str_t										 *ret;

  part = &r->headers_in.headers.part;
  header = part->elts;

  for (i = 0; /* void */; i++) {

      if (i >= part->nelts) {
          if (part->next == NULL) {
              break;
          }

          part = part->next;
          header = part->elts;
          i = 0;
      }

			if (header[i].key.len == x_progress_id.len && ngx_strncmp(header[i].key.data, x_progress_id.data,header[i].key.len) == 0)
			{
				ret = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
				ret->data = header[i].value.data;
				ret->len = header[i].value.len;
				return ret;
			}
  }

	/* not found, check as a reaquest arg */
	if (r->args.len) {
		p = (u_char *) ngx_strstr(r->args.data, "X-Progress-ID=");

		if (p) {
			start_p = p += 14;
	    while (p < r->args.data + r->args.len) {
	        if (*p++ != '&') {
	            continue;
	        }
			}
			
			ret = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
			ret->data = start_p;
			ret->len = p-start_p;
			return ret;
		}
	}

	return NULL;
}


/* This generates the response for the report */
static ngx_int_t
ngx_http_reportuploads_handler(ngx_http_request_t *r)
{
	ngx_str_t		 *id;
  ngx_buf_t    *b;
  ngx_chain_t   out;
	ngx_http_request_t								 *orig;
  ngx_int_t                       rc, size;
  uint32_t                        hash;
  ngx_slab_pool_t                *shpool;
  ngx_rbtree_node_t              *node, *sentinel;
	ngx_http_uploadprogress_conf_t     *lzcf;
  ngx_http_uploadprogress_ctx_t      *ctx;
  ngx_http_uploadprogress_node_t     *lz;
  ngx_table_elt_t  *expires, *cc, **ccp;

  if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
      return NGX_HTTP_NOT_ALLOWED;
  }

  rc = ngx_http_discard_request_body(r);

  if (rc != NGX_OK) {
      return rc;
  }

	/* get the tracking id if any */
	id = get_tracking_id(r);


	if ( id == NULL )
	{
	  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	                 "reportuploads handler cant find id");
    return NGX_DECLINED;
	}
	
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "reportuploads handler found id: %V", id);

  lzcf = ngx_http_get_module_loc_conf(r, ngx_http_uploadprogress_module);

  if (lzcf->shm_zone == NULL) {
	  	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	                 "reportuploads no shm_zone for id: %V", id);
      return NGX_DECLINED;
  }

	orig = NULL;
  ctx = lzcf->shm_zone->data;
	
  hash = ngx_crc32_short(id->data, id->len);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "reportuploads trying to find block with hash %08XD for id: %V", hash, id);

	/* get the original connection of the upload */
  shpool = (ngx_slab_pool_t *) lzcf->shm_zone->shm.addr;
  ngx_shmtx_lock(&shpool->mutex);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "reportuploads in mutex lock for hash %08XD for id: %V", hash, id);

  node = ctx->rbtree->root;
  sentinel = ctx->rbtree->sentinel;

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "reportuploads root %p, sentinel %p for id: %V", node,sentinel, id);

  while (node != sentinel) {

      if (hash < node->key) {
          node = node->left;
          continue;
      }

      if (hash > node->key) {
          node = node->right;
          continue;
      }

			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		               "reportuploads found matching hash %08XD, node %p for id: %V", hash, node, id);

      /* hash == node->key */

      do {
          lz = (ngx_http_uploadprogress_node_t *) &node->color;

          rc = ngx_memn2cmp(id->data, lz->data, id->len, (size_t) lz->len);

          if (rc == 0) {
						/* found the right one */
						/* lz contains the right node*/
						ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					               "reportuploads found request: %p", lz->r);
						orig = lz->r;
						goto found;
          }

					ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				               "reportuploads oops not the same : lz %V != id %V", lz, id);


          node = (rc < 0) ? node->left : node->right;

      } while (node != sentinel && hash == node->key);

			lz = NULL;
			
			/* couldn't find one */
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		               "reportuploads not matching request");
  }

found:
	ngx_shmtx_unlock(&shpool->mutex);

	/* send the output */
  r->headers_out.content_type.len = sizeof("text/javascript") - 1;
  r->headers_out.content_type.data = (u_char *) "text/javascript";

	/* no-cache */

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
          != NGX_OK)
      {
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

	if ( orig == NULL )
	{
		if (lz != NULL )
		{
			size = sizeof("new Object({ 'state' : 'done' })\r\n");
  	}
		else
		{
			size = sizeof("new Object({ 'state' : 'starting' })\r\n");
  	}
	}
	else if ( orig->err_status == 413)
	{
		size = sizeof("new Object({ 'state' : 'error', 'status' : 413 })\r\n");
	}
	else
	{
		size = sizeof("new Object({ 'state' : 'uploading', 'received' : ") + NGX_INT_T_LEN + sizeof(" })\r\n");
		size += sizeof(", 'size' : ") + NGX_INT_T_LEN;
	}

  b = ngx_create_temp_buf(r->pool, size);
  if (b == NULL) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  out.buf = b;
  out.next = NULL;
	
	if (orig == NULL)
	{
		if (lz == NULL )
		{
			b->last = ngx_cpymem(b->last, "new Object({ 'state' : 'starting' })\r\n",
		                       sizeof("new Object({ 'state' : 'starting' })\r\n") - 1);
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
											               "reportuploads returning starting");
		}
		else 
		{
			b->last = ngx_cpymem(b->last, "new Object({ 'state' : 'done' })\r\n",
		                       sizeof("new Object({ 'state' : 'done' })\r\n") - 1);
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		               "reportuploads returning done");
		}
	}
	else if ( orig->err_status == 413)
	{
		b->last = ngx_cpymem(b->last, "new Object({ 'state' : 'error', 'status' : 413 })\r\n",
	                       sizeof("new Object({ 'state' : 'error', 'status' : 413 })\r\n") - 1);
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "reportuploads returning error 413");
	}
	else
	{
		b->last = ngx_cpymem(b->last,"new Object({ 'state' : 'uploading', 'received' : ", 
			sizeof("new Object({ 'state' : 'uploading', 'received' : ")-1 );
			
		b->last = ngx_sprintf(b->last, "%uO, 'size' : %uO })\r\n", (orig->headers_in.content_length_n - orig->request_body->rest), orig->headers_in.content_length_n);

		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "reportuploads returning %uO / %uO", (orig->headers_in.content_length_n - orig->request_body->rest), orig->headers_in.content_length_n);

	}

	// force no caching for proxy
	

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
This is the post read phase. It registers the upload connection in the rb tree
*/
static ngx_int_t
ngx_http_uploadprogress_handler(ngx_http_request_t *r)
{
  size_t                          n;
	ngx_str_t 												 *id;
  ngx_int_t                       rc;
  uint32_t                        hash;
  ngx_slab_pool_t                *shpool;
  ngx_rbtree_node_t              *node, *sentinel;
	ngx_http_uploadprogress_conf_t     *lzcf;
  ngx_http_uploadprogress_ctx_t      *ctx;
  ngx_http_uploadprogress_node_t     *lz;
	ngx_http_uploadprogress_cleanup_t	 *lzcln;
  ngx_pool_cleanup_t             *cln;

	id = get_tracking_id(r);
	if ( id == NULL )
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
             "trackuploads no id found in POST upload req");
		return NGX_DECLINED;
	}
	
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
           "trackuploads id found: %V", id);

  lzcf = ngx_http_get_module_loc_conf(r, ngx_http_uploadprogress_module);

  if (!lzcf->track) {
	  	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	                 "trackuploads not tracking in this location for id: %V", id);
      return NGX_DECLINED;
  }

  if (lzcf->shm_zone == NULL) {
  	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "trackuploads no shm_zone for id: %V", id);
      return NGX_DECLINED;
  }

  ctx = lzcf->shm_zone->data;
	
  hash = ngx_crc32_short(id->data, id->len);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "trackuploads hash %08XD for id: %V",hash, id);

  cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_uploadprogress_cleanup_t));
  if (cln == NULL) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  shpool = (ngx_slab_pool_t *) lzcf->shm_zone->shm.addr;

  ngx_shmtx_lock(&shpool->mutex);

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
          lz = (ngx_http_uploadprogress_node_t *) &node->color;

          rc = ngx_memn2cmp(id->data, lz->data, id->len, (size_t) lz->len);

          if (rc == 0) {
							ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					               "trackuploads already registered: %V",id);
							/* oops found already one */
              ngx_shmtx_unlock(&shpool->mutex);

              return NGX_HTTP_SERVICE_UNAVAILABLE;
          }

          node = (rc < 0) ? node->left : node->right;

      } while (node != sentinel && hash == node->key);

      break;
  }

  n = offsetof(ngx_rbtree_node_t, color)
      + offsetof(ngx_http_uploadprogress_node_t, data)
      + id->len;

  node = ngx_slab_alloc_locked(shpool, n);
  if (node == NULL) {
      ngx_shmtx_unlock(&shpool->mutex);
      return NGX_HTTP_SERVICE_UNAVAILABLE;
  }

  lz = (ngx_http_uploadprogress_node_t *) &node->color;

  node->key = hash;
  lz->len = (u_char) id->len;
	lz->r = r;
  ngx_memcpy(lz->data, id->data, id->len);

  ngx_rbtree_insert(ctx->rbtree, node);
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "trackuploads: %08XD", node->key);

  ngx_shmtx_unlock(&shpool->mutex);

  cln->handler = ngx_http_uploadprogress_cleanup;
  lzcln = cln->data;

  lzcln->shm_zone = lzcf->shm_zone;
  lzcln->node = node;

  return NGX_DECLINED;
}

static void
ngx_http_uploadprogress_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_http_uploadprogress_node_t  *lzn, *lznt;

    for ( ;; ) {

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

        } else { /* node->key == temp->key */

            lzn = (ngx_http_uploadprogress_node_t *) &node->color;
            lznt = (ngx_http_uploadprogress_node_t *) &temp->color;

            if (ngx_memn2cmp(lzn->data, lznt->data, lzn->len, lznt->len) < 0) {

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

/*
removes the expired node from the upload rbtree
*/
static void
ngx_http_uploadprogress_cleanup(void *data)
{
    ngx_http_uploadprogress_cleanup_t  *lzcln = data;

    ngx_slab_pool_t             *shpool;
    ngx_rbtree_node_t           *node;
    ngx_http_uploadprogress_ctx_t   *ctx;
    ngx_http_uploadprogress_node_t  *lz;

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, lzcln->shm_zone->shm.log, 0,
	           "uploadprogress cleanup called");

    ctx = lzcln->shm_zone->data;
    shpool = (ngx_slab_pool_t *) lzcln->shm_zone->shm.addr;
    node = lzcln->node;
    lz = (ngx_http_uploadprogress_node_t *) &node->color;

    ngx_shmtx_lock(&shpool->mutex);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, lzcln->shm_zone->shm.log, 0,
                   "upload progress cleanup: %08XD", node->key);

    ngx_rbtree_delete(ctx->rbtree, node);
    ngx_slab_free_locked(shpool, node);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, lzcln->shm_zone->shm.log, 0,
			"upload progress cleanup node removed: %08XD", node->key);
    ngx_shmtx_unlock(&shpool->mutex);
}

static ngx_int_t
ngx_http_uploadprogress_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_uploadprogress_ctx_t  *octx = data;

    ngx_slab_pool_t            *shpool;
    ngx_rbtree_node_t          *sentinel;
    ngx_http_uploadprogress_ctx_t  *ctx;

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
ngx_http_uploadprogress_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_uploadprogress_handler;
    return NGX_OK;
}

static void *
ngx_http_uploadprogress_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_uploadprogress_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_uploadprogress_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    return conf;
}


static char *
ngx_http_uploadprogress_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_uploadprogress_conf_t *prev = parent;
  ngx_http_uploadprogress_conf_t *conf = child;

  if (conf->shm_zone == NULL) {
      *conf = *prev;
  }

  return NGX_CONF_OK;
}


static char *
ngx_http_upload_progress(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                     n;
    ngx_str_t                  *value;
    ngx_shm_zone_t             *shm_zone;
    ngx_http_uploadprogress_ctx_t  *ctx;

    value = cf->args->elts;

	  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
	                 "ngx_upload_progress name: %V", &value[1]);

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_uploadprogress_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

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
	                 "ngx_upload_progress name: %V, szhm_zone: %p", value[1], shm_zone);

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "track_uploads \"%V\" is already created",
                        &value[1]);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_uploadprogress_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}

static char *
ngx_http_track_uploads(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_uploadprogress_conf_t  *lzcf = conf;
    ngx_str_t  *value;

	  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
	                 "ngx_track_uploads in");

    value = cf->args->elts;

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
		                 "ngx_track_uploads name: %V", value[1]);

    lzcf->shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                           &ngx_http_uploadprogress_module);
    if (lzcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

		lzcf->track = (u_char)1;

	  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
	                 "ngx_track_uploads name: %V,szhm_zone: %p", value[1], lzcf->shm_zone);

    return NGX_CONF_OK;
}


static char *
ngx_http_report_uploads(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_uploadprogress_conf_t  *lzcf = conf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_str_t  *value;

	  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
	                 "ngx_report_uploads in");

    value = cf->args->elts;

	  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
	                 "ngx_report_uploads name: %V", value[1]);

    lzcf->shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                           &ngx_http_uploadprogress_module);
    if (lzcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

	  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
	                 "ngx_report_uploads name: %V, szhm_zone: %p", value[1], lzcf->shm_zone);

		lzcf->track = (u_char)0;

		/* install our report handler */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_reportuploads_handler;

    return NGX_CONF_OK;
}
