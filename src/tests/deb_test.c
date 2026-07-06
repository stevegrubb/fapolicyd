#include <stddef.h>
#include <string.h>
#include <stdatomic.h>

#include "backend-manager.h"
#include "conf.h"
#include "config.h"
#include "filter.h"
#include "message.h"

#define FILTER_CONF TEST_BASE "/src/tests/fixtures/filter-minimal.conf"

extern atomic_bool stop;

int main(int argc, char* const argv[]) {
  set_message_mode(MSG_STDERR, DBG_YES);
  int rc = 1;

  if (filter_init()) {
    msg(LOG_ERR, "ERROR: filter_init failed");
    return 1;
  }
  if (filter_load_file(FILTER_CONF)) {
    msg(LOG_ERR, "ERROR: filter_load_file failed");
    filter_destroy();
    return 1;
  }

  conf_t conf;
  conf.trust = "debdb";
  if (backend_init(&conf)) {
    msg(LOG_ERR, "ERROR: debdb init failed");
    goto out_filter;
  }
  if (backend_load(&conf)) {
    msg(LOG_ERR, "ERROR: debdb load failed");
    goto out_backend;
  }

  msg(LOG_INFO, "\nDone loading.");

  backend_entry* debdb_entry = backend_get_first();
  backend* debdb = NULL;
  if (debdb_entry != NULL) {
    debdb = debdb_entry->backend;
  } else {
    msg(LOG_ERR, "ERROR: No backends registered.");
  }
  if (debdb == NULL) {
    msg(LOG_ERR, "ERROR: debdb not registered");
    goto out_backend;
  }
  if (strcmp(conf.trust, debdb->name) != 0) {
    msg(LOG_ERR, "ERROR: debdb bad name");
    goto out_backend;
  }

  rc = 0;

out_backend:
  backend_close();
out_filter:
  filter_destroy();

  return rc;
}
