/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2015 pooler
 * Copyright 2015 Giuseppe Perniola
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <proto/exec.h>
#include "jansson/jansson.h"
#include <curl/curl.h>
#include "compat.h"
#include "miner.h"

#define LP_SCANTIME		60
		
enum workio_commands {
	WC_GET_WORK,
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands   cmd;
	struct thr_info		   *thr;
	union {
		struct work	       *work;
	} u;
};

const char *algo_names[] = {
	[ALGO_SCRYPT]  = "scrypt",
	[ALGO_SHA256D] = "sha256d",
};

bool                        opt_debug = false;
bool                        opt_protocol = false;
bool                        opt_benchmark = false;
bool                        opt_redirect = true;
bool                        have_gbt = true;
bool                        allow_getwork = true;
bool                        want_stratum = true;
bool                        have_stratum = false;
bool                        opt_quiet = false;
int                         opt_retries = -1;
int                         opt_fail_pause = 30;
int                         opt_timeout = 0;
int                         opt_scantime = 5;
static const bool           opt_time = true;
enum algos                  opt_algo = ALGO_SCRYPT;
int                         opt_scrypt_n = 1024;
int                         opt_n_threads = 0;
int                         num_processors = 0;
char                        *rpc_url = NULL;
char                        *rpc_userpass = NULL;
char                        *rpc_user = NULL;
char                        *rpc_pass = NULL;
int                         pk_script_size = 0;
unsigned char               pk_script[25] = "";
char                        *pCoinbase_addr = NULL;
char                        coinbase_sig[101] = "";
char                        *opt_cert = NULL;
char                        *opt_proxy = NULL;
long                        opt_proxy_type = CURLPROXY_HTTP;
struct thr_info             *thr_info;
int                         stratum_thr_id = -1;
struct work_restart         *work_restart = NULL;
struct stratum_ctx          stratum;

void                        *pApplog_lock = NULL;
void                        *pStats_lock = NULL;

static unsigned long        accepted_count = 0L;
static unsigned long        rejected_count = 0L;
double                      *thr_hashrates = NULL;

struct option {
	const char *name;
	int        has_arg;
	int        *flag;
	int        val;
};

static char const short_options[] =
	"a:Dp:Px:qr:R:s:T:o:u:O";

static struct option const options[] = {
	{ "algo", 1, NULL, 'a' },
	{ "benchmark", 0, NULL, 1005 },
	{ "cert", 1, NULL, 1001 },
	{ "coinbase-addr", 1, NULL, 1013 },
	{ "coinbase-sig", 1, NULL, 1015 },
	{ "debug", 0, NULL, 'D' },
	{ "no-gbt", 0, NULL, 1011 },
	{ "no-getwork", 0, NULL, 1010 },
	{ "no-redirect", 0, NULL, 1009 },
	{ "pass", 1, NULL, 'p' },
	{ "protocol-dump", 0, NULL, 'P' },
	{ "proxy", 1, NULL, 'x' },
	{ "quiet", 0, NULL, 'q' },
	{ "retries", 1, NULL, 'r' },
	{ "retry-pause", 1, NULL, 'R' },
	{ "scantime", 1, NULL, 's' },
	{ "timeout", 1, NULL, 'T' },
	{ "url", 1, NULL, 'o' },
	{ "user", 1, NULL, 'u' },
	{ "userpass", 1, NULL, 'O' },
	{ 0, 0, 0, 0 }
};

struct work {
	uint32_t data[32];
	uint32_t target[8];

	int height;
	char *txs;
	char *workid;

	char *job_id;
	size_t xnonce2_len;
	unsigned char *xnonce2;
};

static struct work g_work;
static time_t g_work_time;
void *g_pWork_lock = NULL;
static bool submit_old = false;
static char *lp_id;
static volatile bool bStopWork = false;

static inline void work_free(struct work *w)
{
	free(w->txs);
	free(w->workid);
	free(w->job_id);
	free(w->xnonce2);
}

static inline void work_copy(struct work *dest, const struct work *src)
{
	memcpy(dest, src, sizeof(struct work));
	if (src->txs)
		dest->txs = strdup(src->txs);
	if (src->workid)
		dest->workid = strdup(src->workid);
	if (src->job_id)
		dest->job_id = strdup(src->job_id);
	if (src->xnonce2) {       
		dest->xnonce2 = malloc(src->xnonce2_len);
		memcpy(dest->xnonce2, src->xnonce2, src->xnonce2_len);
	}
}

static bool jobj_binary(const json_t *obj, const char *key,
			void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (unlikely(!tmp)) {
		applog(LOG_ERR, "JSON key '%s' not found", key);
		return false;
	}
	hexstr = json_string_value(tmp);
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "JSON key '%s' is not a string", key);
		return false;
	}
	if (!hex2bin(buf, hexstr, buflen))
		return false;

	return true;
}

static bool work_decode(const json_t *val, struct work *work)
{
	int i;

	if (unlikely(!jobj_binary(val, "data", work->data, sizeof(work->data)))) {
		applog(LOG_ERR, "JSON invalid data");
		goto err_out;
	}
	if (unlikely(!jobj_binary(val, "target", work->target, sizeof(work->target)))) {
		applog(LOG_ERR, "JSON invalid target");
		goto err_out;
	}

	for (i = 0; i < ARRAY_SIZE(work->data); i++)
		work->data[i] = le32dec(work->data + i);
	for (i = 0; i < ARRAY_SIZE(work->target); i++)
		work->target[i] = le32dec(work->target + i);

	return true;

err_out:
	return false;
}

#define BLOCK_VERSION_MASK 0x000000ff
#define BLOCK_VERSION_CURRENT 3

static bool gbt_work_decode(const json_t *val, struct work *work)
{
	int i, n;
	uint32_t version, curtime, bits;
	uint32_t prevhash[8];
	uint32_t target[8];
	int cbtx_size;
	unsigned char *cbtx = NULL;
	int tx_count, tx_size;
	unsigned char txc_vi[9];
	unsigned char (*merkle_tree)[32] = NULL;
	bool coinbase_append = false;
	bool submit_coinbase = false;
	bool version_force = false;
	bool version_reduce = false;
	json_t *tmp, *txa;
	bool rc = false;

	tmp = json_object_get(val, "mutable");
	if (tmp && json_is_array(tmp)) {
		n = json_array_size(tmp);
		for (i = 0; i < n; i++) {
			const char *s = json_string_value(json_array_get(tmp, i));
			if (!s)
				continue;
			if (!strcmp(s, "coinbase/append"))
				coinbase_append = true;
			else if (!strcmp(s, "submit/coinbase"))
				submit_coinbase = true;
			else if (!strcmp(s, "version/force"))
				version_force = true;
			else if (!strcmp(s, "version/reduce"))
				version_reduce = true;
		}
	}

	tmp = json_object_get(val, "height");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid height");
		goto out;
	}
	work->height = json_integer_value(tmp);

	tmp = json_object_get(val, "version");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid version");
		goto out;
	}
	version = json_integer_value(tmp);
	if ((version & BLOCK_VERSION_MASK) > BLOCK_VERSION_CURRENT) {
		if (version_reduce) {
			version = (version & ~BLOCK_VERSION_MASK) | BLOCK_VERSION_CURRENT;
		} else if (!version_force) {
			applog(LOG_ERR, "Unrecognized block version: %u", version);
			goto out;
		}
	}

	if (unlikely(!jobj_binary(val, "previousblockhash", prevhash, sizeof(prevhash)))) {
		applog(LOG_ERR, "JSON invalid previousblockhash");
		goto out;
	}

	tmp = json_object_get(val, "curtime");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid curtime");
		goto out;
	}
	curtime = json_integer_value(tmp);

	if (unlikely(!jobj_binary(val, "bits", &bits, sizeof(bits)))) {
		applog(LOG_ERR, "JSON invalid bits");
		goto out;
	}

	/* find count and size of transactions */
	txa = json_object_get(val, "transactions");
	if (!txa || !json_is_array(txa)) {
		applog(LOG_ERR, "JSON invalid transactions");
		goto out;
	}
	tx_count = json_array_size(txa);
	tx_size = 0;
	for (i = 0; i < tx_count; i++) {
		const json_t *tx = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tx, "data"));
		if (!tx_hex) {
			applog(LOG_ERR, "JSON invalid transactions");
			goto out;
		}
		tx_size += strlen(tx_hex) / 2;
	}

	/* build coinbase transaction */
	tmp = json_object_get(val, "coinbasetxn");
	if (tmp) {
		const char *cbtx_hex = json_string_value(json_object_get(tmp, "data"));
		cbtx_size = cbtx_hex ? strlen(cbtx_hex) / 2 : 0;
		cbtx = malloc(cbtx_size + 100);
		if (cbtx_size < 60 || !hex2bin(cbtx, cbtx_hex, cbtx_size)) {
			applog(LOG_ERR, "JSON invalid coinbasetxn");
			goto out;
		}
	} else {
		int64_t cbvalue;
		if (!pk_script_size) {
			if (allow_getwork) {
				applog(LOG_INFO, "No payout address provided, switching to getwork");
				have_gbt = false;
			} else
				applog(LOG_ERR, "No payout address provided");
			goto out;
		}
		tmp = json_object_get(val, "coinbasevalue");
		if (!tmp || !json_is_number(tmp)) {
			applog(LOG_ERR, "JSON invalid coinbasevalue");
			goto out;
		}
		cbvalue = json_is_integer(tmp) ? json_integer_value(tmp) : json_number_value(tmp);
		cbtx = malloc(256);
		le32enc((uint32_t *)cbtx, 1); /* version */
		cbtx[4] = 1; /* in-counter */
		memset(cbtx+5, 0x00, 32); /* prev txout hash */
		le32enc((uint32_t *)(cbtx+37), 0xffffffff); /* prev txout index */
		cbtx_size = 43;
		/* BIP 34: height in coinbase */
		for (n = work->height; n; n >>= 8)
			cbtx[cbtx_size++] = n & 0xff;
		cbtx[42] = cbtx_size - 43;
		cbtx[41] = cbtx_size - 42; /* scriptsig length */
		le32enc((uint32_t *)(cbtx+cbtx_size), 0xffffffff); /* sequence */
		cbtx_size += 4;
		cbtx[cbtx_size++] = 1; /* out-counter */
		le32enc((uint32_t *)(cbtx+cbtx_size), (uint32_t)cbvalue); /* value */
		le32enc((uint32_t *)(cbtx+cbtx_size+4), cbvalue >> 32);
		cbtx_size += 8;
		cbtx[cbtx_size++] = pk_script_size; /* txout-script length */
		memcpy(cbtx+cbtx_size, pk_script, pk_script_size);
		cbtx_size += pk_script_size;
		le32enc((uint32_t *)(cbtx+cbtx_size), 0); /* lock time */
		cbtx_size += 4;
		coinbase_append = true;
	}
	if (coinbase_append) {
		unsigned char xsig[100];
		int xsig_len = 0;
		if (*coinbase_sig) {
			n = strlen(coinbase_sig);
			if (cbtx[41] + xsig_len + n <= 100) {
				memcpy(xsig+xsig_len, coinbase_sig, n);
				xsig_len += n;
			} else {
				applog(LOG_WARNING, "Signature does not fit in coinbase, skipping");
			}
		}
		tmp = json_object_get(val, "coinbaseaux");
		if (tmp && json_is_object(tmp)) {
			void *iter = json_object_iter(tmp);
			while (iter) {
				unsigned char buf[100];
				const char *s = json_string_value(json_object_iter_value(iter));
				n = s ? strlen(s) / 2 : 0;
				if (!s || n > 100 || !hex2bin(buf, s, n)) {
					applog(LOG_ERR, "JSON invalid coinbaseaux");
					break;
				}
				if (cbtx[41] + xsig_len + n <= 100) {
					memcpy(xsig+xsig_len, buf, n);
					xsig_len += n;
				}
				iter = json_object_iter_next(tmp, iter);
			}
		}
		if (xsig_len) {
			unsigned char *ssig_end = cbtx + 42 + cbtx[41];
			int push_len = cbtx[41] + xsig_len < 76 ? 1 :
			               cbtx[41] + 2 + xsig_len > 100 ? 0 : 2;
			n = xsig_len + push_len;
			memmove(ssig_end + n, ssig_end, cbtx_size - 42 - cbtx[41]);
			cbtx[41] += n;
			if (push_len == 2)
				*(ssig_end++) = 0x4c; /* OP_PUSHDATA1 */
			if (push_len)
				*(ssig_end++) = xsig_len;
			memcpy(ssig_end, xsig, xsig_len);
			cbtx_size += n;
		}
	}

	n = varint_encode(txc_vi, 1 + tx_count);
	work->txs = malloc(2 * (n + cbtx_size + tx_size) + 1);
	bin2hex(work->txs, txc_vi, n);
	bin2hex(work->txs + 2*n, cbtx, cbtx_size);

	/* generate merkle root */
	merkle_tree = malloc(32 * ((1 + tx_count + 1) & ~1));
	sha256d(merkle_tree[0], cbtx, cbtx_size);
	for (i = 0; i < tx_count; i++) {
		tmp = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tmp, "data"));
		const int tx_size = tx_hex ? strlen(tx_hex) / 2 : 0;
		unsigned char *tx = malloc(tx_size);
		if (!tx_hex || !hex2bin(tx, tx_hex, tx_size)) {
			applog(LOG_ERR, "JSON invalid transactions");
			free(tx);
			goto out;
		}
		sha256d(merkle_tree[1 + i], tx, tx_size);
		if (!submit_coinbase)
			strcat(work->txs, tx_hex);
	}
	n = 1 + tx_count;
	while (n > 1) {
		if (n % 2) {
			memcpy(merkle_tree[n], merkle_tree[n-1], 32);
			++n;
		}
		n /= 2;
		for (i = 0; i < n; i++)
			sha256d(merkle_tree[i], merkle_tree[2*i], 64);
	}

	/* assemble block header */
	work->data[0] = swab32(version);
	for (i = 0; i < 8; i++)
		work->data[8 - i] = le32dec(prevhash + i);
	for (i = 0; i < 8; i++)
		work->data[9 + i] = be32dec((uint32_t *)merkle_tree[0] + i);
	work->data[17] = swab32(curtime);
	work->data[18] = le32dec(&bits);
	memset(work->data + 19, 0x00, 52);
	work->data[20] = 0x80000000;
	work->data[31] = 0x00000280;

	if (unlikely(!jobj_binary(val, "target", target, sizeof(target)))) {
		applog(LOG_ERR, "JSON invalid target");
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(work->target); i++)
		work->target[7 - i] = be32dec(target + i);

	tmp = json_object_get(val, "workid");
	if (tmp) {
		if (!json_is_string(tmp)) {
			applog(LOG_ERR, "JSON invalid workid");
			goto out;
		}
		work->workid = strdup(json_string_value(tmp));
	}

	rc = true;

out:
	free(cbtx);
	free(merkle_tree);
	return rc;
}

static void share_result(int result, const char *reason)
{
	char s[345];
	double hashrate;
	int i;

	hashrate = 0.;
    LockMutex(pStats_lock);
	for (i = 0; i < opt_n_threads; i++)
		hashrate += thr_hashrates[i];
	result ? accepted_count++ : rejected_count++;
    UnlockMutex(pStats_lock);

	sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", 1e-3 * hashrate);
	applog(LOG_INFO, "accepted: %lu/%lu (%.2f%%), %s khash/s %s",
		   accepted_count,
		   accepted_count + rejected_count,
		   100. * accepted_count / (accepted_count + rejected_count),
		   s,
		   result ? "(yay!!!)" : "(booooo)");

	if (opt_debug && reason)
		applog(LOG_DEBUG, "DEBUG: reject reason: %s", reason);
}

bool submit_upstream_work(struct work *work)
{
	json_t *val, *res, *reason;
	char data_str[2 * sizeof(work->data) + 1];
	char s[345];
	int i;
	bool rc = false;

	/* pass if the previous hash is not the current previous hash */
	if (!submit_old && memcmp(work->data + 1, g_work.data + 1, 32)) {
		if (opt_debug)
			applog(LOG_DEBUG, "DEBUG: stale work detected, discarding");
		return true;
	}

	if (have_stratum) {
		uint32_t ntime, nonce;
		char ntimestr[9], noncestr[9], *xnonce2str, *req;

		le32enc(&ntime, work->data[17]);
		le32enc(&nonce, work->data[19]);
		bin2hex(ntimestr, (const unsigned char *)(&ntime), 4);
		bin2hex(noncestr, (const unsigned char *)(&nonce), 4);
		xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
		req = malloc(256 + strlen(rpc_user) + strlen(work->job_id) + 2 * work->xnonce2_len);
		sprintf(req,
			"{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
			rpc_user, work->job_id, xnonce2str, ntimestr, noncestr);
		free(xnonce2str);

		rc = stratum_send_line(&stratum, req);
		free(req);
		if (unlikely(!rc)) {
			applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
			goto out;
		}
	} else if (work->txs) {
		char *req;

		for (i = 0; i < ARRAY_SIZE(work->data); i++)
			be32enc(work->data + i, work->data[i]);
		bin2hex(data_str, (unsigned char *)work->data, 80);
		if (work->workid) {
			char *params;
			val = json_object();
			json_object_set_new(val, "workid", json_string(work->workid));
			params = json_dumps(val, 0);
			json_decref(val);
			req = malloc(128 + 2*80 + strlen(work->txs) + strlen(params));
			sprintf(req,
				"{\"method\": \"submitblock\", \"params\": [\"%s%s\", %s], \"id\":1}\r\n",
				data_str, work->txs, params);
			free(params);
		} else {
			req = malloc(128 + 2*80 + strlen(work->txs));
			sprintf(req,
				"{\"method\": \"submitblock\", \"params\": [\"%s%s\"], \"id\":1}\r\n",
				data_str, work->txs);
		}
		val = json_rpc_call(stratum.curl, rpc_url, rpc_userpass, req, NULL, 0);
		free(req);
		if (unlikely(!val)) {
			applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
			goto out;
		}

		res = json_object_get(val, "result");
		if (json_is_object(res)) {
			char *res_str;
			bool sumres = false;
			void *iter = json_object_iter(res);
			while (iter) {
				if (json_is_null(json_object_iter_value(iter))) {
					sumres = true;
					break;
				}
				iter = json_object_iter_next(res, iter);
			}
			res_str = json_dumps(res, 0);
			share_result(sumres, res_str);
			free(res_str);
		} else
			share_result(json_is_null(res), json_string_value(res));

		json_decref(val);
	} else {
		/* build hex string */
		for (i = 0; i < ARRAY_SIZE(work->data); i++)
			le32enc(work->data + i, work->data[i]);
		bin2hex(data_str, (unsigned char *)work->data, sizeof(work->data));

		/* build JSON-RPC request */
		sprintf(s,
			"{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}\r\n",
			data_str);

		/* issue JSON-RPC request */
		val = json_rpc_call(stratum.curl, rpc_url, rpc_userpass, s, NULL, 0);
		if (unlikely(!val)) {
			applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
			goto out;
		}

		res = json_object_get(val, "result");
		reason = json_object_get(val, "reject-reason");
		share_result(json_is_true(res), reason ? json_string_value(reason) : NULL);

		json_decref(val);
	}

	rc = true;

out:
	return rc;
}

static const char *getwork_req =
	"{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

#define GBT_CAPABILITIES "[\"coinbasetxn\", \"coinbasevalue\", \"longpoll\", \"workid\"]"

static const char *gbt_req =
	"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
	GBT_CAPABILITIES "}], \"id\":0}\r\n";
static const char *gbt_lp_req =
	"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
	GBT_CAPABILITIES ", \"longpollid\": \"%s\"}], \"id\":0}\r\n";

static bool get_upstream_work(struct work *work)
{
	json_t *val;
	int err;
	bool rc;
	struct timeval tv_start, tv_end, diff;

start:
	gettimeofday(&tv_start, NULL);
	val = json_rpc_call(stratum.curl, rpc_url, rpc_userpass,
			    have_gbt ? gbt_req : getwork_req,
			    &err, have_gbt ? JSON_RPC_QUIET_404 : 0);
	gettimeofday(&tv_end, NULL);

	if (have_stratum) {
		if (val)
			json_decref(val);
		return true;
	}

	if (!have_gbt && !allow_getwork) {
		applog(LOG_ERR, "No usable protocol");
		if (val)
			json_decref(val);
		return false;
	}

	if (have_gbt && allow_getwork && !val && err == CURLE_OK) {
		applog(LOG_INFO, "getblocktemplate failed, falling back to getwork");
		have_gbt = false;
		goto start;
	}

	if (!val)
		return false;

	if (have_gbt) {
		rc = gbt_work_decode(json_object_get(val, "result"), work);
		if (!have_gbt) {
			json_decref(val);
			goto start;
		}
	} else
		rc = work_decode(json_object_get(val, "result"), work);

	if (opt_debug && rc) {
		timeval_subtract(&diff, &tv_end, &tv_start);
		applog(LOG_DEBUG, "DEBUG: got new work in %d ms",
		       diff.tv_sec * 1000 + diff.tv_usec / 1000);
	}

	json_decref(val);

	return rc;
}

static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		work_free(wc->u.work);
		free(wc->u.work);
		break;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc));	/* poison */
	free(wc);
}

static bool workio_get_work(struct workio_cmd *wc)
{
	struct work *ret_work;
	int failures = 0;
	
	ret_work = calloc(1, sizeof(*ret_work));
	if (!ret_work)
		return false;

	/* obtain new work from bitcoin via JSON-RPC */
	while (!get_upstream_work(ret_work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
			free(ret_work);
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "json_rpc_call failed, retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}

	/* send work to requesting thread */
	if (!tq_push(wc->thr->q, ret_work))
		free(ret_work);

	return true;
}

bool workio_submit_work(struct workio_cmd *wc)
{
	int failures = 0;

	/* submit solution to bitcoin via JSON-RPC */
	while (!submit_upstream_work(wc->u.work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "error during submitting");
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "...retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}

	return true;
}

static bool get_work(struct thr_info *thr, struct work *work)
{
	struct workio_cmd *wc;
	struct work *work_heap;

	if (opt_benchmark) {
		memset(work->data, 0x55, 76);
		work->data[17] = swab32(time(NULL));
		memset(work->data + 19, 0x00, 52);
		work->data[20] = 0x80000000;
		work->data[31] = 0x00000280;
		memset(work->target, 0x00, sizeof(work->target));
		return true;
	}

	/* fill out work request message */
	wc = calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->cmd = WC_GET_WORK;
	wc->thr = thr;

	/* send work request to workio thread */
	if (!tq_push(thr_info[stratum_thr_id].q, wc)) {
		workio_cmd_free(wc);
		return false;
	}

	/* wait for response, a unit of work */
    work_heap = tq_popWait(thr_info[stratum_thr_id].q);
	if (!work_heap)
		return false;

	/* copy returned work into storage provided by caller */
	memcpy(work, work_heap, sizeof(*work));
	free(work_heap);

	return true;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
	struct workio_cmd *wc;
	
	/* fill out work request message */
	wc = calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->u.work = malloc(sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;

	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	work_copy(wc->u.work, work_in);

	/* send solution to workio thread */
	if (!tq_push(thr_info[stratum_thr_id].q, wc))
		goto err_out;

	return true;

err_out:
	workio_cmd_free(wc);
	return false;
}

void stop_work()
{
    bStopWork = true;
}

void restart_work()
{
    bStopWork = false;
}

static void stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
{
	unsigned char merkle_root[64];
	int i;

    LockMutex(sctx->pWork_lock);

	free(work->job_id);
	work->job_id = strdup(sctx->job.job_id);
	work->xnonce2_len = sctx->xnonce2_size;
	work->xnonce2 = realloc(work->xnonce2, sctx->xnonce2_size);
	memcpy(work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);

	/* Generate merkle root */
	sha256d(merkle_root, sctx->job.coinbase, sctx->job.coinbase_size);
	for (i = 0; i < sctx->job.merkle_count; i++) {
		memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
		sha256d(merkle_root, merkle_root, 64);
	}
	
	/* Increment extranonce2 */
	for (i = 0; i < sctx->xnonce2_size && !++sctx->job.xnonce2[i]; i++);

	/* Assemble block header */
	memset(work->data, 0, 128);
	work->data[0] = le32dec(sctx->job.version);
	for (i = 0; i < 8; i++)
		work->data[1 + i] = le32dec((uint32_t *)sctx->job.prevhash + i);
	for (i = 0; i < 8; i++)
		work->data[9 + i] = be32dec((uint32_t *)merkle_root + i);
	work->data[17] = le32dec(sctx->job.ntime);
	work->data[18] = le32dec(sctx->job.nbits);
	work->data[20] = 0x80000000;
	work->data[31] = 0x00000280;

    UnlockMutex(sctx->pWork_lock);

	if (opt_debug) {
		char *xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
		applog(LOG_DEBUG, "DEBUG: job_id='%s' extranonce2=%s ntime=%08x",
		       work->job_id, xnonce2str, swab32(work->data[17]));
		free(xnonce2str);
	}

	if (opt_algo == ALGO_SCRYPT)
		diff_to_target(work->target, sctx->job.diff / 65536.0);
	else
		diff_to_target(work->target, sctx->job.diff);
}

void *miner_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	int thr_id = mythr->id;
	struct work work = {{0}};
	uint32_t max_nonce;
	uint32_t end_nonce = 0xffffffffU / opt_n_threads * (thr_id + 1) - 0x20;
	unsigned char *scratchbuf = NULL;
	char s[16];
	int i;
	
	if (opt_algo == ALGO_SCRYPT) {
		scratchbuf = scrypt_buffer_alloc(opt_scrypt_n);
		if (!scratchbuf) {
			applog(LOG_ERR, "scrypt buffer allocation failed");
            LockMutex(pApplog_lock);
            return NULL;
		}
	}

    while (!bStopWork)
    {
		unsigned long hashes_done;
		struct timeval tv_start, tv_end, diff;
		int64_t max64;
		int rc;

		if (have_stratum) {
			while (time(NULL) >= g_work_time + 120)
			{
				sleep(1);
				if (bStopWork)
				{
                    break;
                }
            }
            LockMutex(g_pWork_lock);
			if (work.data[19] >= end_nonce && !memcmp(work.data, g_work.data, 76))
				stratum_gen_work(&stratum, &g_work);
		} else {
			int min_scantime = opt_scantime;
			/* obtain new work from internal workio thread */
            LockMutex(g_pWork_lock);
			if (!have_stratum &&
			    (time(NULL) - g_work_time >= min_scantime ||
			     work.data[19] >= end_nonce)) {
				if (unlikely(!get_work(mythr, &g_work))) {
					applog(LOG_ERR, "work retrieval failed, exiting "
						"mining thread %d", mythr->id);
                    UnlockMutex(g_pWork_lock);
					goto out;
				}
				g_work_time = have_stratum ? 0 : time(NULL);
			}
			if (have_stratum) {
                UnlockMutex(g_pWork_lock);
				continue;
			}
		}
		if (memcmp(work.data, g_work.data, 76)) {
			work_free(&work);
			work_copy(&work, &g_work);
			work.data[19] = 0xffffffffU / opt_n_threads * thr_id;
		} else
			work.data[19]++;
        UnlockMutex(g_pWork_lock);
		work_restart[thr_id].restart = 0;
		
		/* adjust max_nonce to meet target scan time */
		if (have_stratum)
			max64 = LP_SCANTIME;
		else
			max64 = g_work_time + opt_scantime - time(NULL);
		max64 *= thr_hashrates[thr_id];
		if (max64 <= 0) {
			switch (opt_algo) {
			case ALGO_SCRYPT:
				max64 = opt_scrypt_n < 16 ? 0x3ffff : 0x3fffff / opt_scrypt_n;
				break;
			case ALGO_SHA256D:
				max64 = 0x1fffff;
				break;
			}
		}
		if (work.data[19] + max64 > end_nonce)
			max_nonce = end_nonce;
		else
			max_nonce = work.data[19] + max64;
		
		hashes_done = 0;
		gettimeofday(&tv_start, NULL);

		/* scan nonces for a proof-of-work hash */
		switch (opt_algo) {
		case ALGO_SCRYPT:
			rc = scanhash_scrypt(thr_id, work.data, scratchbuf, work.target,
			                     max_nonce, &hashes_done, opt_scrypt_n);
			break;

		case ALGO_SHA256D:
			rc = scanhash_sha256d(thr_id, work.data, work.target,
			                      max_nonce, &hashes_done);
			break;

		default:
			/* should never happen */
			goto out;
		}

		/* record scanhash elapsed time */
		gettimeofday(&tv_end, NULL);
		timeval_subtract(&diff, &tv_end, &tv_start);
		if (diff.tv_usec || diff.tv_sec) {
            LockMutex(pStats_lock);
			thr_hashrates[thr_id] =
				hashes_done / (diff.tv_sec + 1e-6 * diff.tv_usec);
            UnlockMutex(pStats_lock);
		}
		if (!opt_quiet) {
			sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.0f" : "%.2f",
				1e-3 * thr_hashrates[thr_id]);
			applog(LOG_INFO, "thread %d: %lu hashes, %s khash/s",
				thr_id, hashes_done, s);
		}
		if (opt_benchmark && thr_id == opt_n_threads - 1) {
			double hashrate = 0.;
			for (i = 0; i < opt_n_threads && thr_hashrates[i]; i++)
				hashrate += thr_hashrates[i];
			if (i == opt_n_threads) {
				sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", 1e-3 * hashrate);
				applog(LOG_INFO, "Total: %s khash/s", s);
			}
		}
		
		/* if nonce found, submit work */
		if (rc && !opt_benchmark && !submit_work(mythr, &work))
			break;
	}

out:
	tq_freeze(mythr->q);
	
	bStopWork = true;

	return NULL;
}

static void restart_threads(void)
{
	int i;

	for (i = 0; i < opt_n_threads; i++)
		work_restart[i].restart = 1;
}

static bool stratum_handle_response(char *buf)
{
	json_t *val, *err_val, *res_val, *id_val;
	json_error_t err;
	bool ret = false;

	val = JSON_LOADS(buf, &err);
	if (!val) {
		applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");
	id_val = json_object_get(val, "id");

	if (!id_val || json_is_null(id_val) || !res_val)
		goto out;

	share_result(json_is_true(res_val),
		err_val ? json_string_value(json_array_get(err_val, 1)) : NULL);

	ret = true;
out:
	if (val)
		json_decref(val);

	return ret;
}

void *stratum_thread(void *userdata)
{
    char            *s;
    int             ret;
    long            flags;
	struct thr_info *mythr = userdata;
	int             timeout = 1000000;
	
    stratum.url = tq_popWait(mythr->q);
	if (!stratum.url)
		goto out;
	applog(LOG_INFO, "Starting Stratum on %s", stratum.url);
	
	flags = opt_benchmark || strncasecmp(rpc_url, "stratum+tcps://", 15) ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL) : CURL_GLOBAL_ALL;
	if (curl_global_init(flags))
    {
		applog(LOG_ERR, "CURL initialization failed");
		
		return NULL;
	}

    stratum.pNetData = SysNetInit();
    
    while (!bStopWork)
    {
		int failures = 0;

        while (!stratum.curl && !bStopWork)
        {
            timeout = 1000000;
            
            LockMutex(g_pWork_lock);
			g_work_time = 0;
            UnlockMutex(g_pWork_lock);

			restart_threads();

			if (!stratum_connect(&stratum, stratum.url) ||
			    !stratum_subscribe(&stratum) ||
			    !stratum_authorize(&stratum, rpc_user, rpc_pass)) {
				stratum_disconnect(&stratum);
				if (opt_retries >= 0 && ++failures > opt_retries) {
					applog(LOG_ERR, "...terminating stratum thread");
					//tq_push(thr_info[stratum_thr_id].q, NULL);
					goto out;
				}
				applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
				sleep(opt_fail_pause);
			}
		}
		
		if (stratum.job.job_id &&
		    (!g_work_time || strcmp(stratum.job.job_id, g_work.job_id))) {
            LockMutex(g_pWork_lock);
			stratum_gen_work(&stratum, &g_work);
			time(&g_work_time);
            UnlockMutex(g_pWork_lock);
			if (stratum.job.clean) {
				applog(LOG_INFO, "Stratum requested work restart");
				restart_threads();
			}
		}
		
		ret = stratum_socket_full_usec(&stratum, timeout);
		if (ret > 0)
		{
            timeout = 1000000;
            
            s = stratum_recv_line(&stratum);
            if (s)
            {
                if (!stratum_handle_method(&stratum, s))
                {
                    stratum_handle_response(s);
                }
                free(s);
            }
            else
            {
                stratum_disconnect(&stratum);
                applog(LOG_ERR, "Stratum connection interrupted");
            }
		}
		else if (ret < 0)
		{
            timeout = 1000000;
            
            stratum_disconnect(&stratum);
			applog(LOG_ERR, "Stratum connection interrupted");
		}
		else
		{
            while (true)
            {
                struct workio_cmd *wc;

                wc = tq_popNoWait(mythr->q);
                if (wc)
                {
                    timeout = 1000000;
                    
                    if (wc->cmd == WC_GET_WORK)
                    {
                        workio_get_work(wc);
                    }
                    else if (wc && wc->cmd == WC_SUBMIT_WORK)
                    {
                        workio_submit_work(wc);
                    }
                    
                    workio_cmd_free(wc);
                }
                else
                {
                    timeout *= 2;
                    if (timeout > 120000000)            // 120 seconds
                    {
                        timeout = 1000000;
                        
                        applog(LOG_ERR, "Stratum connection timed out");

                        stratum_disconnect(&stratum);
                        applog(LOG_ERR, "Stratum connection interrupted");
                    }

                    break;
                }
            }
		}
	}

out:
    tq_freeze(mythr->q);
    
    bStopWork = true;
    
    SysNetDeleteSocket(stratum.pSocket);
    stratum.pSocket = NULL;
    
    if (stratum.curl)
    {
        curl_easy_cleanup(stratum.curl);
        stratum.curl = NULL;
    }
    
    SysNetShutdown(stratum.pNetData);

	return NULL;
}

static void strhide(char *s)
{
	if (*s) *s++ = 'x';
	while (*s) *s++ = '\0';
}

bool check_algo(const char *pAlgo)
{
    int i;
    int v;
    
    for (i = 0; i < ARRAY_SIZE(algo_names); i++)
    {
	   v = strlen(algo_names[i]);
	   if (!strncmp(pAlgo, algo_names[i], v))
       {
	       if (pAlgo[v] == '\0')
           {
		      return true;
		   }
		   if (pAlgo[v] == ':' && i == ALGO_SCRYPT)
           {
		      char *ep;
			  v = strtol(pAlgo + v + 1, &ep, 10);
			  if (*ep || v & (v-1) || v < 2)
			  {
			     continue;
              }
			
			  return true;
		   }
	    }
    }
    
    return false;
}

void set_algo(const char *pAlgo)
{
    int i;
    int v;

    for (i = 0; i < ARRAY_SIZE(algo_names); i++)
    {
	   v = strlen(algo_names[i]);
	   if (!strncmp(pAlgo, algo_names[i], v))
       {
	       if (pAlgo[v] == '\0')
           {
		      opt_algo = i;
		      if (i == ALGO_SCRYPT)
		      {
                opt_scrypt_n = 1024;
              }
		      
		      return;
		   }
		   if (pAlgo[v] == ':' && i == ALGO_SCRYPT)
           {
		      char *ep;
			  v = strtol(pAlgo + v + 1, &ep, 10);
			  if (*ep || v & (v-1) || v < 2)
			  {
			     continue;
              }
              
              opt_algo = i;
			  opt_scrypt_n = v;

			  return;
		   }
	    }
    }
    
    opt_algo = ALGO_SCRYPT;
    opt_scrypt_n = 1024;
}

void parse_arg(int key, char *arg, const char *pname)
{
	char *p;
	int v, i;

	switch(key) {
	case 'a':
		for (i = 0; i < ARRAY_SIZE(algo_names); i++) {
			v = strlen(algo_names[i]);
			if (!strncmp(arg, algo_names[i], v)) {
				if (arg[v] == '\0') {
					opt_algo = i;
					break;
				}
				if (arg[v] == ':' && i == ALGO_SCRYPT) {
					char *ep;
					v = strtol(arg+v+1, &ep, 10);
					if (*ep || v & (v-1) || v < 2)
						continue;
					opt_algo = i;
					opt_scrypt_n = v;
					break;
				}
			}
		}
		if (i == ARRAY_SIZE(algo_names)) {
			fprintf(stderr, "%s: unknown algorithm -- '%s'\n",
				pname, arg);
		}
		break;
	case 'q':
		opt_quiet = true;
		break;
	case 'D':
		opt_debug = true;
		break;
	case 'p':
		free(rpc_pass);
		rpc_pass = strdup(arg);
		strhide(arg);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 'r':
		v = atoi(arg);
		if (v < -1 || v > 9999)	/* sanity check */
			return;
		opt_retries = v;
		break;
	case 'R':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			return;
		opt_fail_pause = v;
		break;
	case 's':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			return;
		opt_scantime = v;
		break;
	case 'T':
		v = atoi(arg);
		if (v < 0 || v > 99999)	/* sanity check */
			return;
		opt_timeout = v;
		break;
	case 'u':
		free(rpc_user);
		rpc_user = strdup(arg);
		break;
	case 'o': {			/* --url */
		char *ap, *hp;
		ap = strstr(arg, "://");
		ap = ap ? ap + 3 : arg;
		hp = strrchr(arg, '@');
		if (hp) {
			*hp = '\0';
			p = strchr(ap, ':');
			if (p) {
				free(rpc_userpass);
				rpc_userpass = strdup(ap);
				free(rpc_user);
				rpc_user = calloc(p - ap + 1, 1);
				strncpy(rpc_user, ap, p - ap);
				free(rpc_pass);
				rpc_pass = strdup(++p);
				if (*p) *p++ = 'x';
				v = strlen(hp + 1) + 1;
				memmove(p + 1, hp + 1, v);
				memset(p + v, 0, hp - p);
				hp = p;
			} else {
				free(rpc_user);
				rpc_user = strdup(ap);
			}
			*hp++ = '@';
		} else
			hp = ap;
		if (ap != arg) {
			if (strncasecmp(arg, "stratum+tcp://", 14) &&
			    strncasecmp(arg, "stratum+tcps://", 15)) {
				fprintf(stderr, "%s: unknown protocol -- '%s'\n",
					pname, arg);
	            return;
			}
			free(rpc_url);
			rpc_url = strdup(arg);
			strcpy(rpc_url + (ap - arg), hp);
		} else {
			if (*hp == '\0' || *hp == '/') {
				fprintf(stderr, "%s: invalid URL -- '%s'\n",
					pname, arg);
                return;
            }
			free(rpc_url);
			rpc_url = malloc(strlen(hp) + 8);
			sprintf(rpc_url, "http://%s", hp);
		}
		have_stratum = !opt_benchmark && !strncasecmp(rpc_url, "stratum", 7);
		break;
	}
	case 'O':			/* --userpass */
		p = strchr(arg, ':');
		if (!p) {
			fprintf(stderr, "%s: invalid username:password pair -- '%s'\n",
				pname, arg);
            return;
		}
		free(rpc_userpass);
		rpc_userpass = strdup(arg);
		free(rpc_user);
		rpc_user = calloc(p - arg + 1, 1);
		strncpy(rpc_user, arg, p - arg);
		free(rpc_pass);
		rpc_pass = strdup(++p);
		strhide(p);
		break;
	case 'x':			/* --proxy */
		if (!strncasecmp(arg, "socks4://", 9))
			opt_proxy_type = CURLPROXY_SOCKS4;
		else if (!strncasecmp(arg, "socks5://", 9))
			opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
		else if (!strncasecmp(arg, "socks4a://", 10))
			opt_proxy_type = CURLPROXY_SOCKS4A;
		else if (!strncasecmp(arg, "socks5h://", 10))
			opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
		else
			opt_proxy_type = CURLPROXY_HTTP;
		free(opt_proxy);
		opt_proxy = strdup(arg);
		break;
	case 1001:
		free(opt_cert);
		opt_cert = strdup(arg);
		break;
	case 1005:
		opt_benchmark = true;
		want_stratum = false;
		have_stratum = false;
		break;
	case 1009:
		opt_redirect = false;
		break;
	case 1010:
		allow_getwork = false;
		break;
	case 1011:
		have_gbt = false;
		break;
	case 1013:			/* --coinbase-addr */
	    free(pCoinbase_addr);
	    pCoinbase_addr = strdup(arg);
		pk_script_size = address_to_script(pk_script, sizeof(pk_script), arg);
		if (!pk_script_size) {
			fprintf(stderr, "%s: invalid address -- '%s'\n",
				pname, arg);
		}
		break;
	case 1015:			/* --coinbase-sig */
		if (strlen(arg) + 1 > sizeof(coinbase_sig)) {
			fprintf(stderr, "%s: coinbase signature too long\n", pname);
            return;
		}
		strcpy(coinbase_sig, arg);
		break;
    }
}

bool parse_config(json_t *config, const char *pname, const char *ref)
{
	int i;
	char *s;
	json_t *val;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		if (!options[i].name)
			break;

		val = json_object_get(config, options[i].name);
		if (!val)
			continue;

		if (options[i].has_arg && json_is_string(val)) {
			if (!strcmp(options[i].name, "config")) {
				fprintf(stderr, "%s: %s: option '%s' not allowed here\n",
					pname, ref, options[i].name);				
                return false;
			}
			s = strdup(json_string_value(val));
			if (!s)
				break;
			parse_arg(options[i].val, s, pname);
			free(s);
		} else if (!options[i].has_arg && json_is_true(val)) {
			parse_arg(options[i].val, "", pname);
		} else {
			fprintf(stderr, "%s: invalid argument for option '%s'\n",
				pname, options[i].name);
			return false;
		}
	}
	
	return true;
}

bool save_config(const char *pFilename)
{
    char    string[128];
    int     i;
    int     ret;
    json_t  *jdata;
    json_t  *jval;
    
    if (!pFilename || strlen(pFilename) <= 0)
    {
        return false;
    }
    
    jdata = json_object();
    
    for (i = 0; i < ARRAY_SIZE(options); i++)
    {
		if (!options[i].name)
			break;
			
		jval = NULL;
		
		switch (options[i].val)
		{
        	case 'a':
            {
                if (opt_algo == ALGO_SCRYPT)
                {
                    sprintf(string, "%s:%d", algo_names[opt_algo], opt_scrypt_n);
                }
                else
                {
                    sprintf(string, "%s", algo_names[opt_algo]);
                }
                
                jval = json_string(string);
        		
        		break;
            }
            
        	case 'q':
                if (opt_quiet)
                {
                    jval = json_true();
                }
               
        		break;
        		
        	case 'D':
        		if (opt_debug)
                {
                    jval = json_true();
                }
                        		
        		break;
        		
        	case 'p':
                jval = json_string(rpc_pass);
        		
        		break;
        		
        	case 'P':
        		if (opt_protocol)
        		{
                    jval = json_true();
                }
        		
        		break;
        		
        	case 'r':
                sprintf(string, "%d", opt_retries);
        		jval = json_string(string);
        		
        		break;
        		
        	case 'R':
                sprintf(string, "%d", opt_fail_pause);
        		jval = json_string(string);
        		
        		break;
        		
        	case 's':
                sprintf(string, "%d", opt_scantime);
        		jval = json_string(string);
        		
        		break;
        		
        	case 'T':
                sprintf(string, "%d", opt_timeout);
        		jval = json_string(string);
        		
        		break;
        		
        	case 'u':
        		jval = json_string(rpc_user);
        		
        		break;
        		
        	case 'o':
                jval = json_string(rpc_url);
        		
        		break;
        		
        	case 'x':
        		jval = json_string(opt_proxy);
        		
        		break;
        		
        	case 1001:
        		jval = json_string(opt_cert);
        		
        		break;
        		
        	case 1005:
        		if (opt_benchmark)
        		{
                    jval = json_true();
                }
        		
        		break;
        		
        	case 1009:
        		if (!opt_redirect)
        		{
                    jval = json_true();
                }
        		
        		break;
        		
        	case 1010:
        		if (!allow_getwork)
        		{
                    jval = json_true();
                }
        		
        		break;
        		
        	case 1011:
        		if (!have_gbt)
        		{
                    jval = json_true();
                }
        		
        		break;
        		
        	case 1013:
        	    jval = json_string(pCoinbase_addr);
        		
        		break;
        		
        	case 1015:
        		jval = json_string(coinbase_sig);
        		
        		break;            
        }
			
		if (jval)
		{
		  json_object_set_new(jdata, options[i].name, jval);
        }
    }
    
    ret = json_dump_file(jdata, pFilename, JSON_INDENT(3));
    
    json_decref(jdata);
    
    return ret == 0;
}
