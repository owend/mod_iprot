/*
 * iProtect for Apache
 *
 * Copyright 1999-2003, Digital Concepts
 *
 * http://www.digital-concepts.net
 */

#include "mod_iprot.h"

/* set timeout that aborts transactions??? */

int new_str_from_datum(const DBT *d, char **str, request_rec *r)
{
#if 1
  *str = PSTRDUP(r->pool, d->data);
  return (*str) ? TRUE : FALSE;
#else
  *str = PALLOC(r->pool, d->size);
  if (!*str) {  /* out of memory */
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "new_str_from_datum()");
    return FALSE;
  }
  strncpy(*str, d->data, d->size);
  return TRUE;
#endif
} /* new_str_from_datum */

DB_ENV *create_db_env(char *db_home,
		      int extra_flags,
		      int mode, server_rec *s)
{
  int result;
  DB_ENV *db_envp;

  /* create database environment, needed for transactions and locking */
  if ((result = db_env_create(&db_envp, 0)) != 0) {
    ap_log_error(APLOG_MARK, APLOG_ERR, s,
		 "db_env_create: %s",
		 db_strerror(result));
    return NULL;
  }

  /* db_envp->set_errfile(stderr); */
  db_envp->set_errpfx(db_envp, "iprot");

  if ((result =
       db_envp->set_lk_detect(db_envp, DB_LOCK_YOUNGEST)) != 0) {
					/* Abort the youngest transaction. */
    ap_log_error(APLOG_MARK, APLOG_ERR, s,
		 "conf_rec->db_envp->set_lk_detect: %s",
		 db_strerror(result));
    return NULL;
  }

  /* initialize database environment */
  if ((result = db_envp->open(db_envp, db_home,
			      DB_CREATE | DB_INIT_MPOOL | DB_INIT_LOCK |
			      DB_INIT_LOG | DB_INIT_TXN | extra_flags,
			      mode)) != 0) {
    ap_log_error(APLOG_MARK, APLOG_ERR, s,
		 "db_envp->open: %s %s",
		 db_strerror(result), db_home);
    return NULL;
  }

  return db_envp;
} /* create_db_env */

DB *open_db(DB_ENV *db_envp,
	    const char *filename,
	    const int flags,
	    const int mode,
	    server_rec *s)
{
  DB *dbp;
  int result;

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "open_db(): pid %i", (int)getpid());

  /* Create the database handle and open the underlying database. */
  if ((result = db_create(&dbp, db_envp, 0)) != 0) {
    ap_log_error(APLOG_MARK, APLOG_ERR, s,
		 "(error number %i) pid %i",
		 result, (int)getpid());
    return NULL;
  }

  if ((result =
       dbp->open(dbp, filename, NULL,
		 DB_TYPE, DB_CREATE | flags, mode)) != 0) {
    ap_log_error(APLOG_MARK, APLOG_ERR, s,
		 "filename: %s (error number %i) pid %i",
		 filename, result, (int)getpid());
    return NULL;
  }

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "leaving open_db(): pid %i", (int)getpid());

  return dbp;
} /* open_db */

int close_db_env(DB_ENV **db_envp, server_rec *s)
{
  DB_ENV *envp;
  int result;

  if (*db_envp) {
    envp = *db_envp;
    if ((result = envp->close(envp, 0)) != 0) {
      ap_log_error(APLOG_MARK, APLOG_ERR, s,
		   "db_envp->close: %s",
		   db_strerror(result));
    }
    *db_envp = NULL;
  }

  return result;
} /* close_db_env */

void close_db(DB **dbp, server_rec *s)
{
  DB *db;

  if (*dbp) {
    db = *dbp;
    db->close(db, 0); /* DB_NOSYNC */
    *dbp = NULL;
  }
} /* close_db */

int transaction_start(server_rec *s, 
		      DB_ENV *db_envp,
		      DB_TXN *parent_txn_id,
		      DB_TXN **txn_id,
		      u_int32_t flags)
{
  int result;

  if ((result = txn_begin(db_envp,
			  parent_txn_id, txn_id, flags)) != 0) {
    ap_log_error(APLOG_MARK, APLOG_ERR, s, db_strerror(result));
  }

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
		 "transaction_start(): pid %i: result %i",
		 (int)getpid(), result);

  return result;
} /* transaction_start */

void transaction_abort(server_rec *s, DB_TXN *txn_id)
{
  int result;

  if ((result = txn_abort(txn_id)) != 0)
    ap_log_error(APLOG_MARK, APLOG_ERR, s, db_strerror(result));

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "transaction_abort(): pid %i: result %i",
	       (int)getpid(), result);
} /* transaction_abort */

void transaction_commit(server_rec *s, DB_TXN *txn_id, u_int32_t flags)
{
  int result;

  /* DB_TXN_NOSYNC or DB_TXN_SYNC */
  if ((result = txn_commit(txn_id, flags)) != 0)
    ap_log_error(APLOG_MARK, APLOG_ERR, s, db_strerror(result));

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, s,
	       "transaction_commit(): pid %i: result %i",
	       (int)getpid(), result);
} /* transaction_commit */

int get_record(DB_TXN *txn_id,
	       DB *db,
	       DBT *db_data,
	       const char *host,
	       const char *target,
	       request_rec *r)
{
  DBT db_key;
  int flags = 0;
  int result;

  /* Initialize key/data structures. */
  memset(&db_key, 0, sizeof(DBT));
  memset(db_data, 0, sizeof(DBT));

  db_key.size = strlen(target) + strlen(host) + 2;
  db_key.data = (char *)PALLOC(r->pool, db_key.size);
  if (!db_key.data) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "get_record()");
    db_data->data = NULL;
    return ENOMEM;
  }

  strncpy(db_key.data, target, db_key.size);
  strncat(db_key.data + strlen(target), "?", db_key.size);
  strncat(db_key.data + strlen(target) + 1, host, db_key.size);

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r,
	       "get_record: pid %i: key.data %s",
	       (int)getpid(), (char *)db_key.data);

  if ((result = db->get(db, txn_id, &db_key, db_data, flags)) != 0) {
    db_data->data = NULL;  /* DB_LOCK_DEADLOCK -30996, DB_NOTFOUND -30991 */
    if ((result != DB_LOCK_DEADLOCK) && (result != DB_NOTFOUND)) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "get_record: %s", db_strerror(result));
    }
  }

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r,
	       "get_record: pid %i: result %i: data.data \"%s\"",
	       (int)getpid(), result, (char *)db_data->data);

  return result;
} /* get_record */

int get_cursor(DB_TXN *txn_id,
	       DB *db,
	       DBC **cursorp,
	       request_rec *r)
{
  int result;

  if ((result = db->cursor(db, txn_id, cursorp, 0)) != 0) {
    if ((result != DB_LOCK_DEADLOCK) && (result != DB_NOTFOUND)) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "get_cursor: %s", db_strerror(result));
    }
  }

  return result;
} /* get_cursor */

int get_cursor_record(DB_TXN *txn_id,
		      DBC *cursorp,
		      DBT *db_key,
		      DBT *db_data,
		      u_int32_t flags,
		      request_rec *r)
{
  int result;

  /* Initialize key/data structures. */
  memset(db_key, 0, sizeof(DBT));
  memset(db_data, 0, sizeof(DBT));

  if ((result = cursorp->c_get(cursorp, db_key, db_data, flags)) != 0) {
    if (result == DB_NOTFOUND) {
      db_data->data = NULL;
    } else {
      if (result != DB_LOCK_DEADLOCK) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		      "get_cursor_record: %s", db_strerror(result));
      }
    }
  }

  return result;
} /* get_cursor_record */

int store_record(DB_TXN *txn_id,
		 DB *db,
		 const char *host,
		 const char *target,
		 const char *value,
		 const request_rec *r)
{
  DBT db_key, db_data;
  int result;

  /* Initialize key/data structures. */
  memset(&db_key, 0, sizeof(DBT));
  memset(&db_data, 0, sizeof(DBT));

  db_key.size = strlen(target) + strlen(host) + 2;
  if (!(db_key.data = PALLOC(r->pool, db_key.size))) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", db_strerror(errno));
    return ENOMEM;
  }
  strncpy(db_key.data, target, db_key.size);
  strncat(db_key.data + strlen(target), "?", db_key.size);
  strncat(db_key.data + strlen(target) + 1, host, db_key.size);

  db_data.size = strlen(value) + 1;	/* copy the terminating NULL */
  db_data.data = PALLOC(r->pool, db_data.size);
  if (!db_data.data) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "store_record()");
    return ENOMEM;
  }
  strncpy(db_data.data, value, db_data.size);
  	
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r,
		"store_record: pid %i", (int)getpid());
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r,
		"key data: \"%s\" size %i, data data: \"%s\" size %i",
		(char *)db_key.data, db_key.size,
		(char *)db_data.data, db_data.size);

  if ((result = db->put(db, txn_id, &db_key, &db_data, 0)) != 0) {
    if (result != DB_LOCK_DEADLOCK) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "store_record: %s", db_strerror(result));
    }
  }

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r,
	       "store_record: pid %i: result %i: data.data \"%s\"",
	       (int)getpid(), result, (char *)db_data.data);

  return result;
} /* store_record */

int delete_record(DB_TXN *txn_id,
		  DB *db,
		  const char *host,
		  const char *target,
		  const request_rec *r)
{
  DBT db_key;
  int result;

  /* Initialize key/data structures. */
  memset(&db_key, 0, sizeof(DBT));

  db_key.size = strlen(target) + strlen(host) + 2;
  db_key.data = PALLOC(r->pool, db_key.size);
  if (!db_key.data) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "delete_record()");
    return ENOMEM;
  }
  strncpy(db_key.data, target, db_key.size);
  strncat(db_key.data + strlen(target), "?", db_key.size);
  strncat(db_key.data + strlen(target) + 1, host, db_key.size);

  if ((result = db->del(db, NULL, &db_key, 0)) != 0) {
		printf("db: %s: key was deleted.\n", (char *)db_key.data);
    if (result != DB_LOCK_DEADLOCK) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "delete_record: %s", db_strerror(result));
    }
  }

  return result;
} /* delete_record */

static int split_data_strings(request_rec *r,
			      const char *str,
			      char **p_str_1,
			      char **p_str_2,
			      char **p_str_3,
			      char **p_str_4)
{
  char *s, *p;

  if (!(s = (char *) PSTRDUP (r->pool, str))) {  /* out of memory */
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "split_data_strings()");
    return FALSE;
  }

  if (p_str_1) {
    *p_str_1 = s;

    if ((p = strchr(*p_str_1, DATA_STR_SEP_C))) {
      p[0] = '\0';

      if (p_str_2) {
	*p_str_2 = &p[1];

	if ((p = strchr(*p_str_2, DATA_STR_SEP_C))) {
	  p[0] = '\0';

	  if (p_str_3) {
	    *p_str_3 = &p[1];

	    if ((p = strchr(*p_str_3, DATA_STR_SEP_C))) {
	      p[0] = '\0';

	      if (p_str_4)
		*p_str_4 = &p[1];
	    }
	  }
	}
      }
    }
  }

  return TRUE;
} /* split_data_strings */

int get_data_strings(request_rec *r,
		     const DBT *d,
		     char **p_str_1,
		     char **p_str_2,
		     char **p_str_3,
		     char **p_str_4)
{
  if (d->data) {
    char *temp_str;

    new_str_from_datum(d, &temp_str, r);
    if (!temp_str) {  /* out of memory */
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "get_data_strings()");
      return FALSE;
    }

    if (!(split_data_strings(r, temp_str, p_str_1, p_str_2, p_str_3, p_str_4)))
      return FALSE;
  }

  return TRUE;
} /* get_data_strings */

char *combine_data_strings(request_rec *r,
			   const char *str_1,
			   const char *str_2,
			   const char *str_3,
			   const char *str_4)
{
  char *str;
  int len = 4; /* for separators and terminator */
  char data_str_sep_c = DATA_STR_SEP_C;
  char *data_str_sep = (char *) PALLOC (r->pool, 2);

  snprintf(data_str_sep, 2, "%c", data_str_sep_c);
  			/* a simple cast doesn't work */

  if (str_1)
    len += strlen(str_1);
  if (str_2)
    len += strlen(str_2);
  if (str_3)
    len += strlen(str_3);
  if (str_4)
    len += strlen(str_4);

  str = (char *) PALLOC(r->pool, len);
  if (!str) {  /* out of memory */
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "combine_data_strings()");
    return NULL;
  }
  strcpy(str, ""); /* need an empty string to strcat() to */

  if (str_1) {
    strcat(str, str_1);

    if (str_2) {
      strcat(str, data_str_sep);
      strcat(str, str_2);

      if (str_3) {
	strcat(str, data_str_sep);
	strcat(str, str_3);

	if (str_4) {
	  strcat(str, data_str_sep);
	  strcat(str, str_4);
	}
      }
    }
  }

  return str;
} /* combine_data_strings */

/*
 * returns 1: blocked, 0: ignored, -1: no record
 * if the block has expired blockedStr is changed to ""
 */
char block_ignore_status(request_rec *r, char **blockedStr)
{
  time_t timestamp;

  if (!*blockedStr || !strcmp(*blockedStr, ""))
    return 0; /* no record */

  timestamp = atoi(strchr(*blockedStr, (int) ':') + 1);

  printf("timestamp is %i\n", (int) timestamp);
  printf("request_time is %i\n", (int) r->request_time);

  if ((timestamp != 0) && (r->request_time >= timestamp)) {
    *blockedStr = "";
    return 0;
  }

  switch ((int) *blockedStr[0]) {
  case 'I': return -1;
  case 'B': return 1;
  default: return 0;
  }

  return 0;
} /* block_ignore_status */ 

char block_ignore_expired(DB *db,
			  const char *host,
			  const char *key, 
			  const time_t timestamp,
			  const time_t request_time)
{
  if ((timestamp != 0) && (request_time >= timestamp)) {
    /* clean up or delete record here */
    return TRUE;
  }

  return FALSE;
}

char isipaddress(const prot_config_rec *config_rec, const char *item)
{
  return !ap_regexec(config_rec->ipaddress_preg, item, 0, NULL, 0);
} /* isusername */

void get_items(char *item, char **item_1, char **item_2, request_rec *r)
{
  char *buffer = (char *)PSTRDUP(r->pool, item);

  *item_1 = strtok(buffer, "?\xbf");
  *item_2 = strtok(NULL, "\x0");
}

static int update_iprot_db(request_rec *r)
{
  server_rec *s = r->server;
  DB_TXN *txn_id;
  DBT db_key, db_data, d;
  DBC *cursorp;
  int result;

  prot_config_rec *config_rec =	/* module config rec */
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  if (!config_rec->block_ignore_db) /* ?? */
    return FALSE;

  /* abort and retry */
  if (FALSE) {
  retry:
    transaction_abort(s, txn_id);
  }

  /* transaction_start */
  if ((result = transaction_start(s, config_rec->db_envp,
				  NULL, &txn_id, DB_TXN_FLAGS)) != 0) {
    return FALSE;
  }

  if ((result =
       get_cursor(txn_id, config_rec->block_ignore_db, &cursorp, r)) != 0) {
    if (result == DB_LOCK_DEADLOCK) {
      goto retry;
    } else {
      transaction_abort(s, txn_id);
      return FALSE;
    }
  }

  if ((result = get_cursor_record(txn_id, cursorp,
				  &db_key, &db_data, DB_FIRST, r)) != 0) {
    if (result == DB_LOCK_DEADLOCK) {
      goto retry;
    } else {
      transaction_abort(s, txn_id);
      if (result == DB_NOTFOUND)
	return TRUE;
      else
	return FALSE;
    }
  }

  while (!result) {
    char *key = NULL, *str = NULL;
    char *target = NULL, *server_hostname = NULL;
    char *DataStr = NULL;
    char *BlockIgnoreStr = "";
    char *SuccessfulIPStr = "";
    char *FailedIPStr = "";
    char *BWStr = "";

    if (!new_str_from_datum(&db_key, &key, r) ||
	!new_str_from_datum (&db_data, &BlockIgnoreStr, r)) {
      transaction_abort(s, txn_id);
      return FALSE;
    }

    get_items(key, &target, &server_hostname, r);

    if (!target || !server_hostname) {
      transaction_abort(s, txn_id);
      return FALSE;
    }

    /* if get_record() doesn't return a record
       get_data_strings() returns null strings */
    if ((result = get_record(txn_id, config_rec->iprot_db,
			     &d, server_hostname, target, r)) != 0) {
      if (result != DB_NOTFOUND) {
	if (result == DB_LOCK_DEADLOCK) {
	  goto retry;
	} else {
	  transaction_abort(s, txn_id);
	  return FALSE; /* I/O Error */
	}
      }
    }

    if (isipaddress(config_rec, target)) { /* target is ip address */
      get_data_strings(r, &d, &SuccessfulIPStr, &str, NULL, NULL);
      DataStr = combine_data_strings(r, SuccessfulIPStr,
				     BlockIgnoreStr, "", NULL);
    } else { /* target is username */
      get_data_strings(r, &d,
		       &SuccessfulIPStr, &FailedIPStr, &str, &BWStr);
      DataStr = combine_data_strings(r, SuccessfulIPStr, FailedIPStr,
				     BlockIgnoreStr, BWStr);
    }

    if (!DataStr) {  /* out of memory */
      transaction_abort(s, txn_id);
      return FALSE;
    }

    LOG_PRINTF(s, "DataStr is '%s'", DataStr);

    if ((result =
	 store_record(txn_id, config_rec->iprot_db,
		      server_hostname, target, DataStr, r)) != 0) {
      if (result == DB_LOCK_DEADLOCK) {
	goto retry;
      } else {
	transaction_abort(s, txn_id);
	return FALSE;
      }
    }

    if ((result = get_cursor_record(txn_id, cursorp,
				    &db_key, &db_data, DB_FIRST, r)) != 0) {
      if (result == DB_LOCK_DEADLOCK) {
	goto retry;
      } else {
	transaction_abort(s, txn_id);
	if (result == DB_NOTFOUND)
	  return TRUE;
	else
	  return FALSE;
      }
    }
  } /* while */

  /* store update flag record */
  db_key.size = strlen(UPDATED_KEY);
  db_key.data = PALLOC(r->pool, db_key.size);
  if (!db_key.data) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "update_iprot_db()");
    transaction_abort(s, txn_id);	/* out of memory */
    return FALSE;
  }
  strncpy(db_key.data, UPDATED_KEY, db_key.size);

  db_data.data = PALLOC(r->pool, 12);
  if (!db_data.data) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "update_iprot_db()");
    transaction_abort(s, txn_id);	/* out of memory */
    return FALSE;
  }
  sprintf(db_data.data, "%li", r->request_time);
  db_data.size = strlen(db_data.data);

  if ((result =
       config_rec->iprot_db->put(config_rec->iprot_db,
				 txn_id, &db_key, &db_data, 0)) != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		  "DB->put: %s", db_strerror(result));
    if (result == DB_LOCK_DEADLOCK) {
      goto retry;
    } else {
      transaction_abort(s, txn_id);
      return FALSE;
    }
  }

  transaction_commit(s, txn_id, 0);

  return TRUE;
} /* update_iprot_db */

DB *open_iprot_db(DB_ENV *db_envp,
		  const char *filename,
		  const int flags,
		  const int mode,
		  request_rec *r)
{
  server_rec *s = r->server;

  DB *iprot_db;
  DB_TXN *txn_id;
  DBT db_key, db_data;

  int result;

  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  /* Initialize key/data structures. */
  memset(&db_key, 0, sizeof(DBT));
  memset(&db_data, 0, sizeof(DBT));

  /* look for update flag record */
  db_key.size = strlen(UPDATED_KEY);
  db_key.data = PSTRDUP(r->pool, UPDATED_KEY);
  if (!db_key.data) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", "open_iprot_db()");
    return FALSE;
  }

  if (!(iprot_db = open_db(config_rec->db_envp, config_rec->filename,
			   flags, mode, s)))
    return NULL;

  /* abort and retry */
  if (FALSE) {
  retry:
    transaction_abort(s, txn_id);
  }

  /* transaction_start */
  if ((result = transaction_start(s, config_rec->db_envp,
				  NULL, &txn_id, DB_TXN_FLAGS)) != 0) {
    return NULL;
  }

  if ((result = iprot_db->get(iprot_db, NULL,
			      &db_key, &db_data, flags)) != 0) {
    if (result == DB_NOTFOUND) {
      update_iprot_db(r);
    } else {
      if (result == DB_LOCK_DEADLOCK) {
	goto retry;
      } else {
	transaction_abort(s, txn_id);
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		      "DB->get: %s", db_strerror(result));
	return FALSE;
      }
    }
  }

  transaction_commit(s, txn_id, DB_TXN_FLAGS);
  return iprot_db;
} /* open_iprot_db */

int delete_block_ignore(request_rec *r,
			const char *server_hostname,
			const char *target,
			enum del_types action)
{
  server_rec *s = r->server;

  DB_TXN *txn_id;
  int result_1, result_2;
				 
  prot_config_rec *config_rec =
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  /* transaction_start */
  if ((result_1 = transaction_start(s, config_rec->db_envp,
				    NULL, &txn_id, DB_TXN_FLAGS)) != 0) {
    return FALSE;
  }

  if (action == BLOCK_IGNORE_DELETE) {
    if (delete_record(txn_id, config_rec->block_ignore_db,
		      server_hostname, target, r) == 0)
      result_1 = TRUE;
    else
      result_1 = FALSE;
  }
  /* if error continue and try to delete from iprot db */

  /* delete from iprot_db */
  if (delete_record(txn_id, config_rec->iprot_db,
		    server_hostname, target, r))
    result_2 = TRUE;
  else
    result_2 = FALSE;

  transaction_commit(s, txn_id, 0);
  return result_1 && result_2;
} /* delete_block_ignore */

int check_block_ignore(const char *BlockIgnoreStr,
		       const char *server_hostname,
		       const char *target,
		       request_rec *r)
{
  /* Returns: error: -1, no block or ignore: 0, blocked: 1 ignored: -1 */

  time_t timestamp = atoi(strchr(BlockIgnoreStr, ':') + 1);
				 
  if (timestamp && (timestamp <= r->request_time)) { /* expired */
    delete_block_ignore(r, server_hostname, target, BLOCK_DELETE);
    return 0;
  }

  if (BlockIgnoreStr[0] == 'I')
    return -1;
  if (BlockIgnoreStr[0] == 'B')
    return 1;

  return 0;
} /*  check_block_ignore */

int get_footprint_list(char *footprintStr, footprint *footprint_list,
		       time_t request_time, time_t *expires)
{
  int i, count = 0;
  char item[ITEM_SIZE];
  time_t timestamp;
  int num_ips = 0;
  char *str_p;

  *expires = 2147483647L;

  num_ips = (str_p = strtok(footprintStr, "?\xbf")/* ? & ¿ */) ?
    atoi(str_p) : 0;
  
  for (i = 0; i < num_ips; i++) {
    strncpy(item, (str_p = strtok(NULL, ":")) ? str_p : "", ITEM_SIZE);
    timestamp = (time_t) (str_p = strtok(NULL, ";")) ? atol(str_p) : 0;

    if (timestamp > request_time && strcmp(item, "")) {
      strncpy(footprint_list[count].item, item, ITEM_SIZE);
      footprint_list[count].timestamp = timestamp;
      if (timestamp < *expires) *expires = timestamp;
      count++;
    }
  }

  return count;
} /* get_footprint_list */

/* Return true if timestamp is a different calendar day from block_time. */
int diff_day(time_t block_time, time_t current_time)
{
  struct tm ts_1;
  struct tm ts_2;

#if THREAD_SAFE
  localtime_r(&block_time, &ts_1);
  localtime_r(&current_time, &ts_2);
#else
  /* make copies as localtime() uses a static buffer */
  memcpy(&ts_1, localtime(&block_time), sizeof(ts_1));
  memcpy(&ts_2, localtime(&current_time), sizeof(ts_2));
#endif

  if ((ts_2.tm_mday > ts_1.tm_mday) ||
      (ts_2.tm_mon > ts_1.tm_mon) ||
      (ts_2.tm_year > ts_1.tm_year))
    return TRUE;

  return FALSE;
} /* diff_day */

int periodic_block_expired(time_t block_time,
			   time_t timeout,
			   time_t current_time)
{
  return ((block_time + (timeout * SEC_PER_HOUR)) < current_time) ?
    TRUE : FALSE;
} /* periodic_block_expires */

time_t block_expires(time_t block_time,
		     time_t timeout,
		     time_t current_time)
{
  struct tm ts;

  if (timeout) {
    if (periodic_block_expired(block_time, timeout, current_time))
      return -1;

    return (block_time + (timeout * SEC_PER_HOUR));
  } else {
    if (diff_day(block_time, current_time))
      return -1;

#if THREAD_SAFE
    localtime_r(&block_time, &ts);
#else
    /* make a copy as localtime() uses a static buffer */
    memcpy(&ts, localtime(&block_time), sizeof(ts));
#endif
    ts.tm_sec = 59;
    ts.tm_min = 59;
    ts.tm_hour = 23;

    return mktime(&ts);
  }

} /* block_expires */
