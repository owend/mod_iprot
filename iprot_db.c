/*
 * iProtect for Apache
 *
 * Copyright 1999-2003, Digital Concepts
 *
 * http://www.digital-concepts.net
 */

#include "mod_iprot.h"

int new_str_from_datum(const datum *d, char **str, request_rec *r)
{
  *str = PALLOC (r->pool, d->dsize + 1);
  if (!str) {  /* out of memory */
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    return FALSE;
  }
  strncpy(*str, d->dptr, d->dsize);
  /* gdbm only free (d.dptr); */
  (*str)[d->dsize] = '\0';
  return TRUE;
} /* new_str_from_datum */

DBM *open_db(const char *filename, const int flags,
	     const int mode, request_rec *r)
{
  DBM *db;

  if (!(db = dbm_open(filename, flags, mode)))
    ap_log_reason("Can't open db file.", filename, r);

  return db;
}

int get_record(DBM *db, datum *d,
	       const char *host, const char *key,
	       const request_rec *r)
{
  datum k;
  k.dsize = strlen(key) + strlen(host) + 1;
  k.dptr = PALLOC (r->pool, k.dsize + 2);
  if (!k.dptr) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    d->dptr = NULL;
    return FALSE;
  }
  strcpy (k.dptr, key);
  strcat (k.dptr + strlen (key), "?");
  strcat (k.dptr + strlen (key) + 1, host);

  *d = dbm_fetch(db, k);
  return TRUE;
} /* get_record */

int store_record(DBM *db, const char *host, const char *key,
		  const char *value, const request_rec *r)
{
  datum k, v;

  k.dsize = strlen(key) + strlen(host) + 1;
  if (!(k.dptr = PALLOC(r->pool, k.dsize + 1))) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    return FALSE;
  }
  strcpy(k.dptr, key);
  strcat(k.dptr + strlen(key), "?");
  strcat(k.dptr + strlen(key) + 1, host);

  v.dsize = strlen(value);
  v.dptr = PALLOC(r->pool, v.dsize + 1);
  if (!v.dptr) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    return FALSE;
  }
  strncpy(v.dptr, value, v.dsize); /* don't copy the terminating NULL */

  if (dbm_store(db, k, v, DBM_REPLACE)) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    return FALSE;
  } else {
    return TRUE;
  }
} /* store_record */

int delete_record(DBM *db, const char *host,
		  const char *key, const request_rec *r)
{
  datum k;

  k.dsize = strlen(key) + strlen(host) + 1;
  k.dptr = PALLOC (r->pool, k.dsize + 1);
  if (!k.dptr) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    return FALSE;
  }
  strcpy(k.dptr, key);
  strcat(k.dptr + strlen(key), "?");
  strcat(k.dptr + strlen(key) + 1, host);

  if (dbm_delete(db, k)) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "Error deleting record.");
    return FALSE;
  } else {
    return TRUE;
  }
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
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
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
		     const datum *d,
		     char **p_str_1,
		     char **p_str_2,
		     char **p_str_3,
		     char **p_str_4)
{
  if (d->dptr) {
    char *temp_str;

    new_str_from_datum(d, &temp_str, r);
    if (!temp_str) {  /* out of memory */
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
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
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
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

char block_ignore_expired(DBM *db,
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

void get_items(char *item, char **item_1, char **item_2)
{
  *item_1 = strtok(item, "?\xbf");
  *item_2 = strtok(NULL, "\x0");
}

static int update_iprot_db(request_rec *r, DBM **iprot_db)
{
  server_rec *s = r->server;
  DBM *block_ignore_db;
  datum db_key, db_nextkey, db_data, d;

  prot_config_rec *config_rec =	/* module config rec */
    (prot_config_rec *) GET_MODULE_CONFIG(s->module_config, &iprot_module);

  if (!config_rec->block_ignore_filename) /* ?? */
    return FALSE;

  if (!(block_ignore_db = open_db(config_rec->block_ignore_filename,
				  IPROT_DB_FLAGS, 0664, r)))
    return FALSE;

  db_key = dbm_firstkey(block_ignore_db);

  while (db_key.dptr) {
    char *key = NULL, *str = NULL;
    char *target = NULL, *server_hostname = NULL;
    char *DataStr = NULL;
    char *BlockIgnoreStr = "";
    char *SuccessfulIPStr = "";
    char *FailedIPStr = "";
    char *BWStr = "";

    db_data = dbm_fetch(block_ignore_db, db_key);
    if (!new_str_from_datum(&db_key, &key, r) ||
	!new_str_from_datum (&db_data, &BlockIgnoreStr, r)) {
      dbm_close(block_ignore_db);
      return FALSE;
    }

    get_items(key, &target, &server_hostname);

    if (!target || !server_hostname ||
	!get_record(*iprot_db, &d, server_hostname, target, r))	{
      dbm_close(block_ignore_db);
      return FALSE;
    }
    /* if get_record() doesn't return a record
       get_data_strings() returns null strings */

    if (isipaddress(config_rec, target)) { /* target is ip address */
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
      get_data_strings(r, &d, &SuccessfulIPStr, &str, NULL, NULL);
      DataStr = combine_data_strings(r, SuccessfulIPStr,
				     BlockIgnoreStr, "", NULL);
    } else { /* target is username */
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
      get_data_strings(r, &d,
		       &SuccessfulIPStr, &FailedIPStr, &str, &BWStr);
      DataStr = combine_data_strings(r, SuccessfulIPStr, FailedIPStr,
				     BlockIgnoreStr, BWStr);
    }

    if (!DataStr) {  /* out of memory */
      dbm_close(block_ignore_db);
      return FALSE;
    }

    LOG_PRINTF(s, "DataStr is '%s'", DataStr);

    if (!store_record(*iprot_db, server_hostname, target, DataStr, r)) {
      dbm_close(block_ignore_db);
      return FALSE;
    }

    db_nextkey = dbm_nextkey(block_ignore_db);
    db_key = db_nextkey;
  } /* while */

  dbm_close(block_ignore_db);

  /* store update flag record */
  db_key.dsize = strlen(UPDATED_KEY);
  db_key.dptr = PALLOC(r->pool, db_key.dsize);
  if (!db_key.dptr) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    dbm_close(*iprot_db);
    return FALSE;
  }
  strncpy(db_key.dptr, UPDATED_KEY, db_key.dsize);

  db_data.dptr = PALLOC(r->pool, 12);
  if (!db_data.dptr) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    dbm_close(*iprot_db);
    return FALSE;
  }
  sprintf(db_data.dptr, "%li", r->request_time);
  db_data.dsize = strlen(db_data.dptr);

  if (dbm_store(*iprot_db, db_key, db_data, DBM_REPLACE)) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    dbm_close(*iprot_db);
    return FALSE;
  }

  return TRUE;
} /* update_iprot_db */

DBM *open_iprot_db(const char *filename, const int flags,
		   const int mode, request_rec *r)
{
  DBM *iprot_db;
  datum db_key, db_data;

  if (!(iprot_db = open_db(filename, flags, mode, r)))
    return NULL;

  /* look for update flag record */
  db_key.dsize = strlen(UPDATED_KEY);
  db_key.dptr = PALLOC(r->pool, db_key.dsize);
  if (!db_key.dptr) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, r, "%s", strerror(errno));
    dbm_close(iprot_db);
    return FALSE;
  }

  strncpy(db_key.dptr, UPDATED_KEY, db_key.dsize);
  db_data = dbm_fetch(iprot_db, db_key);

  if (!db_data.dptr)
    update_iprot_db(r, &iprot_db);

  return iprot_db;
} /* open_iprot_db */

int delete_block_ignore(request_rec *r, DBM *block_ignore_db, DBM *iprot_db,
			const char *server_hostname, const char *target,
			enum del_types action)
{
  if (action == BLOCK_IGNORE_DELETE)
    delete_record(block_ignore_db, server_hostname, target, r);
  /* if error continue and try to delete from iprot db */

  /* delete from iprot_db */
  if (!delete_record(iprot_db, server_hostname, target, r))
    return FALSE;

  return TRUE;
} /* delete_block_ignore */

int check_block_ignore(const char *BlockIgnoreStr, DBM *iprot_db,
		       const char *server_hostname, const char *target,
		       prot_config_rec *config_rec, request_rec *r)
{
  /* Returns: error: -1, no block or ignore: 0, blocked: 1 ignored: -1 */

  DBM *block_ignore_db;
  time_t timestamp = atoi(strchr(BlockIgnoreStr, ':') + 1);

  if (timestamp && (timestamp <= r->request_time)) { /* expired */
    if (!(block_ignore_db = open_db(config_rec->block_ignore_filename,
				    IPROT_DB_FLAGS, 0664, r)))
      return -1; /* error */

    delete_block_ignore(r, block_ignore_db, iprot_db,
			server_hostname, target, BLOCK_DELETE);
    dbm_close(block_ignore_db);
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

int diff_day(time_t time_1, time_t time_2)
{
    struct tm ts_1;
    struct tm ts_2;

    /* make copies as localtime() uses a static buffer */
    memcpy(&ts_1, localtime(&time_1), sizeof(ts_1));
    memcpy(&ts_2, localtime(&time_2), sizeof(ts_2));

    if ((ts_2.tm_year > ts_1.tm_year) ||
	(ts_2.tm_mon > ts_1.tm_mon) ||
	(ts_2.tm_mday > ts_1.tm_mday))
	return TRUE;

    return FALSE;
} /* diff_day */

