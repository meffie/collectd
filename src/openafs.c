/**
 * collectd - src/openafs.c
 * Copyright (C) 2015       Michael Meffie
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Michael Meffie <mmeffie at sinenomine.net>
 */

#include "collectd.h"
#include "plugin.h"
#include "common.h"
#include "utils_avltree.h"
#include "utils_complain.h"
#include "utils_latency.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <pthread.h>

/*
 * Data Source
 *
 * For now, create a custom data type so we do not have to overwrite the
 * types.db file which is installed by the base collectd package.
 */
static data_source_t openafs_dsrc[1] =
{
  {"value", DS_TYPE_DERIVE, 0.0, NAN }
};

/* Data Set */
static data_set_t openafs_ds =
{
  "volume_access", STATIC_ARRAY_SIZE (openafs_dsrc), openafs_dsrc
};


/* Configuration */
static const char *config_keys[] =
{
  "FileAuditLog",
};
static int config_keys_num = STATIC_ARRAY_SIZE (config_keys);
static char *openafs_file_audit_log = NULL;

/* OpenAFS sys-v message queue style audit log. */
#define AUDIT_PROJ_ID 1

static pthread_mutex_t mq_thread_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t mq_thread;
static _Bool     mq_thread_running = 0;
static _Bool     mq_thread_shutdown = 0;

struct mq_buffer_s
{
    long mtype;
    char mtext[2048];
};

/* OpenAFS audit message tags. */
#define TAG_UNKNOWN -1 /* unrecognized tag */
#define TAG_EVENT   1  /* audit event name */
#define TAG_CODE    2  /* audit event code */
#define TAG_STR     3  /* string */
#define TAG_INT     4  /* int */
#define TAG_HOST    5  /* host address as ipv4 quad */
#define TAG_LONG    6  /* long */
#define TAG_DATE    7  /* data as unix epoch */
#define TAG_FID     8  /* FID <volume>:<vnode>:<uniq> */
#define TAG_FIDS    9  /* list of FIDs. eg. FIDS 2 FID ... FID ... */
#define TAG_NAME    10 /* user name */
#define TAG_ID      11 /* user id */
#define TAG_ACL     12 /* ACL string */


static c_avl_tree_t   *volume_tree = NULL;
static pthread_mutex_t volume_tree_lock = PTHREAD_MUTEX_INITIALIZER;

struct volume_metric_s
{
  int seen;             /* This volume seen in audit log since last dispatch. */
  derive_t vol_access;  /* volume accesses seen in audit log. */
};
typedef struct volume_metric_s volume_metric_t;

/* volume_tree_lock must be held by caller. */
static volume_metric_t* volume_metric_lookup(char *volume)
{
  volume_metric_t *metric;
  int status;
  char *volume_copy;

  status = c_avl_get (volume_tree, volume, (void *) &metric);
  if (status == 0)
    return (metric);

  volume_copy = strdup(volume);
  if (volume_copy == NULL)
  {
    ERROR ("openafs plugin: strdup failed.");
    return (NULL);
  }
  metric = malloc (sizeof(*metric));
  if (metric == NULL)
  {
    ERROR ("openafs plugin: malloc failed.");
    sfree (volume_copy);
    return (NULL);
  }
  memset (metric, 0, sizeof(*metric));
  status = c_avl_insert (volume_tree, volume_copy, metric);
  if (status != 0)
  {
    ERROR ("openafs plugin: c_avl_instert failed.");
    sfree (volume_copy);
    sfree (metric);
    return (NULL);
  }
  return (metric);
}

static int volume_metric_add_access(char *volume)
{
  volume_metric_t *metric;

  pthread_mutex_lock (&volume_tree_lock);

  metric = volume_metric_lookup (volume);
  if (metric == NULL)
  {
    pthread_mutex_unlock (&volume_tree_lock);
    return (-1);
  }

  metric->seen = 1;
  metric->vol_access++;

  pthread_mutex_unlock (&volume_tree_lock);
  return (0);
}

/* volume_tree_lock must be held by caller. */
static int volume_metric_submit(char *volume, volume_metric_t *metric)
{
  value_t values[1];
  value_list_t vl = VALUE_LIST_INIT;

  sstrncpy (vl.host, hostname_g, sizeof (vl.host));
  sstrncpy (vl.plugin, "openafs", sizeof (vl.plugin));
  sstrncpy (vl.type, "volume_access", sizeof (vl.type));
  sstrncpy (vl.type_instance, volume, sizeof (vl.type_instance)); /* string of digits */
  vl.values = values;
  vl.values_len = 1;
  vl.values[0].derive = metric->vol_access;

  plugin_dispatch_values (&vl);
  return (0);
}

static int audit_tag (char *token)
{
  int tag;

  if (strcmp (token, "EVENT") == 0) {
    tag = TAG_EVENT;
  } else if (strcmp(token, "CODE") == 0) {
    tag = TAG_CODE;
  } else if (strcmp(token, "NAME") == 0) {
    tag = TAG_NAME;
  } else if (strcmp(token, "HOST") == 0) {
    tag = TAG_HOST;
  } else if (strcmp(token, "STR") == 0) {
    tag = TAG_STR;
  } else if (strcmp(token, "INT") == 0) {
    tag = TAG_INT;
  } else if (strcmp(token, "LONG") == 0) {
    tag = TAG_LONG;
  } else if (strcmp(token, "DATE") == 0) {
    tag = TAG_DATE;
  } else if (strcmp(token, "FID") == 0) {
    tag = TAG_FID;
  } else if (strcmp(token, "FIDS") == 0) {
    tag = TAG_FIDS;
  } else if (strcmp(token, "ID") == 0) {
    tag = TAG_ID;
  } else if (strcmp(token, "ACL") == 0) {
    tag = TAG_ACL;
  } else {
    DEBUG ("openafs plugin: unknown tag \"%s\"", token);
    tag = TAG_UNKNOWN;
  }
  return (tag);
}

static int split_fid(char *fid, char *delims, char **fields, size_t size)
{
  size_t i = 0;
  char *dummy = fid;
  char *saveptr = NULL;

  while ((fields[i] = strtok_r (dummy, delims, &saveptr)) != NULL)
  {
    dummy = NULL;
    i++;
    if (i >= size)
      break;
  }
  return (i);
}

static int parse_audit_msg (char *text)
{
  size_t count = 0;
  char *dummy = text;
  char *saveptr = NULL;
  char *token;
  int tag = 0;
  int num_fields;
  char *fields[3];
  char *volume;

  while ((token = strtok_r (dummy, " ", &saveptr)) != NULL) {
    dummy = NULL;
    count++;
    if (count < 7)
    {
      continue;  /* skip timestamp and thread number */
    }
    if (tag == 0)
    {
      tag = audit_tag (token);
      continue; /* get value next */
    }
    switch (tag)
    {
    case TAG_FID:
      num_fields = split_fid (token, ":", fields, 3);
      if (num_fields == 3)
      {
        volume = fields[0];
        DEBUG ("openafs plugin: volume=%s", volume);
        volume_metric_add_access(volume);
      }
      break;
    case TAG_HOST:
      DEBUG ("openafs plugin: host=%s", token);
      break;
    case TAG_UNKNOWN:
    case TAG_EVENT:
    case TAG_CODE:
    case TAG_STR:
    case TAG_INT:
    case TAG_LONG:
    case TAG_DATE:
    case TAG_FIDS:
    case TAG_NAME:
    case TAG_ID:
    case TAG_ACL:
       break;
    }
    tag = 0;
  }
  return (0);
}

static void *openafs_mq_thread (void *args)
{
  char *path = openafs_file_audit_log;
  key_t key;
  int mqid;
  size_t len;
  struct mq_buffer_s buffer;
  char errbuf[1024];

  if (path == NULL)
  {
    path = "/usr/afs/logs/FileAudit";
  }
  key = ftok (path, AUDIT_PROJ_ID);
  if (key < 0)
  {
    char errbuf[1024];

    ERROR ("openafs plugin: ftok failed: %s",
      sstrerror (errno, errbuf, sizeof (errbuf)));
    mq_thread_running = 0;
    pthread_exit (NULL);
  }

  mqid = msgget (key, 0);
  if (mqid < 0)
  {
    char errbuf[1024];

    ERROR ("openafs plugin: msgget failed: %s",
      sstrerror (errno, errbuf, sizeof(errbuf)));
    mq_thread_running = 0;
    pthread_exit (NULL);
  }

  while (!mq_thread_shutdown)
  {
    len = msgrcv (mqid, &buffer, sizeof(buffer), 0, 0);

    if (len < 0) {
      if ((errno == EINTR) || (errno == EAGAIN))
      {
        sleep(1);
        continue;
      }
      ERROR ("openafs plugin: msgrcv failed: %s",
          sstrerror (errno, errbuf, sizeof (errbuf)));
      break;
    }
    if (errno != 0)  /* EACESS will return a blank message. */
    {
      ERROR ("openafs plugin: msgrcv failed: %s",
          sstrerror (errno, errbuf, sizeof (errbuf)));
      break;
    }
    //DEBUG ("openafs plugin: audit message: len=%ld, mtype=%ld, mtext=\"%s\"", len, buffer.mtype, buffer.mtext);
    parse_audit_msg (buffer.mtext);
  }
  return (NULL);
}

static int openafs_config (const char *key, const char *value)
{
  if (strcasecmp (key, "FileAuditLog") == 0)
  {
    char *tmp = strdup (value);
    if (tmp == NULL)
      return -1;
    sfree (openafs_file_audit_log);
    openafs_file_audit_log = tmp;
  }
  else
  {
    return (-1);
  }
  return (0);
}

static int openafs_init (void)
{
  DEBUG ("openafs plugin: init");

  pthread_mutex_lock (&volume_tree_lock);
  if (volume_tree == NULL)
  {
    volume_tree = c_avl_create ((void *) strcmp);
  }
  pthread_mutex_unlock (&volume_tree_lock);

  pthread_mutex_lock (&mq_thread_lock);
  if (!mq_thread_running)
  {
    int status;

    status = plugin_thread_create (&mq_thread, NULL, openafs_mq_thread, NULL);
    if (status != 0)
    {
      char errbuf[1024];
      ERROR ("openafs plugin: pthread_create failed: %s",
          sstrerror (errno, errbuf, sizeof (errbuf)));
      return (status);
    }
  }
  mq_thread_running = 1;
  pthread_mutex_unlock (&mq_thread_lock);
  return (0);
}

static int openafs_read (void)
{
  c_avl_iterator_t *iter;
  char *volume;
  volume_metric_t *metric;

  DEBUG ("openafs plugin: read");

  pthread_mutex_lock (&volume_tree_lock);
  if (volume_tree == NULL)
  {
    pthread_mutex_unlock (&volume_tree_lock);
    return (0);
  }

  iter = c_avl_get_iterator (volume_tree);
  while (c_avl_iterator_next (iter, (void *) &volume, (void *) &metric) == 0)
  {
    if (metric->seen)
    {
      volume_metric_submit(volume, metric);
      metric->seen = 0;
    }
  }
  c_avl_iterator_destroy (iter);

  /* TODO: Remove inactive entries every x read intervals? */

  pthread_mutex_unlock (&volume_tree_lock);
  return (0);
}

static int openafs_shutdown (void)
{
  DEBUG ("openafs plugin: shutdown");

  pthread_mutex_lock (&mq_thread_lock);
  if (mq_thread_running)
  {
    mq_thread_shutdown = 1;
    pthread_kill (mq_thread, SIGTERM);
    pthread_join (mq_thread, NULL);
  }
  mq_thread_running = 0;
  pthread_mutex_unlock (&mq_thread_lock);

  return (0);
}

void module_register (void)
{
  plugin_register_config ("openafs", openafs_config, config_keys, config_keys_num);
  plugin_register_data_set (&openafs_ds);
  plugin_register_init ("openafs", openafs_init);
  plugin_register_read ("openafs", openafs_read);
  plugin_register_shutdown ("openafs", openafs_shutdown);
}

