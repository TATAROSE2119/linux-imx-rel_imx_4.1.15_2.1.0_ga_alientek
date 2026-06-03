/*
 * Copyright (C) 2014 Sergey Senozhatsky.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include "zcomp.h"
#include "asm/page.h"
#include "zcomp_lzo.h"
#include <linux/crypto.h>
#include <linux/err.h>

#ifdef CONFIG_ZRAM_LZ4_COMPRESS
#include "zcomp_lz4.h"
#endif

/*
 * single zcomp_strm backend
 */
struct zcomp_strm_single {
	struct mutex strm_lock;
	struct zcomp_strm *zstrm;
};

/*
 * multi zcomp_strm backend
 */
struct zcomp_strm_multi {
	/* protect strm list */
	spinlock_t strm_lock;
	/* max possible number of zstrm streams */
	int max_strm;
	/* number of available zstrm streams */
	int avail_strm;
	/* list of available strms */
	struct list_head idle_strm;
	wait_queue_head_t strm_wait;
};


#if IS_ENABLED(CONFIG_ZRAM_ZSTD_COMPRESS)
/* ==========================================================
 * 骇客魔改区：ZSTD 桥接 Crypto API 的强行注入代码 
 * ========================================================== */

// 1. 创建 Crypto 引擎实例
static void *zstd_crypto_create(void) {
        return crypto_alloc_comp("zstd", 0, 0);
}

// 2. 销毁实例
static void zstd_crypto_destroy(void *private) {
        crypto_free_comp(private);
}

// 3. 压缩：直接呼叫你写的 zstd_compressor.ko
static int zstd_crypto_compress(const unsigned char *src, unsigned char *dst,
                                size_t *dst_len, void *private) {
        struct crypto_comp *comp = private;
        unsigned int dlen = PAGE_SIZE*2; // 预留足够空间
        int ret = crypto_comp_compress(comp, src, PAGE_SIZE, dst, &dlen);
        *dst_len = dlen;
        return ret;
}

// 4. 解压：老内核解压接口居然不传 private 上下文！我们只能用野路子临时申请
static int zstd_crypto_decompress(const unsigned char *src, size_t src_len,
                                  unsigned char *dst) {
        // 强行临时分配一个引擎来解压（虽然有轻微性能损耗，但能完美绕过老 API 限制）
        struct crypto_comp *comp = crypto_alloc_comp("zstd", 0, 0);
        unsigned int dlen = PAGE_SIZE;
        int ret;
        
        if (IS_ERR(comp)) return -EINVAL;
        
        ret = crypto_comp_decompress(comp, src, src_len, dst, &dlen);
        crypto_free_comp(comp);
        return ret;
}

// 5. 伪造出一张名为 "zstd" 的 zram 白名单身份证！
static struct zcomp_backend zcomp_zstd = {
        .compress = zstd_crypto_compress,
        .decompress = zstd_crypto_decompress,
        .create = zstd_crypto_create,
        .destroy = zstd_crypto_destroy,
        .name = "zstd",
};
/* ========================================================== */
#endif


static struct zcomp_backend *backends[] = {
	&zcomp_lzo,
#ifdef CONFIG_ZRAM_LZ4_COMPRESS
	&zcomp_lz4,
#endif
#if IS_ENABLED(CONFIG_ZRAM_ZSTD_COMPRESS)
	&zcomp_zstd,
#endif
	NULL
};

static struct zcomp_backend *find_backend(const char *compress)
{
	int i = 0;
	while (backends[i]) {
		if (sysfs_streq(compress, backends[i]->name))
			break;
		i++;
	}
	return backends[i];
}

static void zcomp_strm_free(struct zcomp *comp, struct zcomp_strm *zstrm)
{
	if (zstrm->private)
		comp->backend->destroy(zstrm->private);
	free_pages((unsigned long)zstrm->buffer, 1);
	kfree(zstrm);
}

/*
 * allocate new zcomp_strm structure with ->private initialized by
 * backend, return NULL on error
 */
static struct zcomp_strm *zcomp_strm_alloc(struct zcomp *comp)
{
	struct zcomp_strm *zstrm = kmalloc(sizeof(*zstrm), GFP_KERNEL);
	if (!zstrm)
		return NULL;

	zstrm->private = comp->backend->create();
	/*
	 * allocate 2 pages. 1 for compressed data, plus 1 extra for the
	 * case when compressed size is larger than the original one
	 */
	zstrm->buffer = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
	if (!zstrm->private || !zstrm->buffer) {
		zcomp_strm_free(comp, zstrm);
		zstrm = NULL;
	}
	return zstrm;
}

/*
 * get idle zcomp_strm or wait until other process release
 * (zcomp_strm_release()) one for us
 */
static struct zcomp_strm *zcomp_strm_multi_find(struct zcomp *comp)
{
	struct zcomp_strm_multi *zs = comp->stream;
	struct zcomp_strm *zstrm;

	while (1) {
		spin_lock(&zs->strm_lock);
		if (!list_empty(&zs->idle_strm)) {
			zstrm = list_entry(zs->idle_strm.next,
					struct zcomp_strm, list);
			list_del(&zstrm->list);
			spin_unlock(&zs->strm_lock);
			return zstrm;
		}
		/* zstrm streams limit reached, wait for idle stream */
		if (zs->avail_strm >= zs->max_strm) {
			spin_unlock(&zs->strm_lock);
			wait_event(zs->strm_wait, !list_empty(&zs->idle_strm));
			continue;
		}
		/* allocate new zstrm stream */
		zs->avail_strm++;
		spin_unlock(&zs->strm_lock);

		zstrm = zcomp_strm_alloc(comp);
		if (!zstrm) {
			spin_lock(&zs->strm_lock);
			zs->avail_strm--;
			spin_unlock(&zs->strm_lock);
			wait_event(zs->strm_wait, !list_empty(&zs->idle_strm));
			continue;
		}
		break;
	}
	return zstrm;
}

/* add stream back to idle list and wake up waiter or free the stream */
static void zcomp_strm_multi_release(struct zcomp *comp, struct zcomp_strm *zstrm)
{
	struct zcomp_strm_multi *zs = comp->stream;

	spin_lock(&zs->strm_lock);
	if (zs->avail_strm <= zs->max_strm) {
		list_add(&zstrm->list, &zs->idle_strm);
		spin_unlock(&zs->strm_lock);
		wake_up(&zs->strm_wait);
		return;
	}

	zs->avail_strm--;
	spin_unlock(&zs->strm_lock);
	zcomp_strm_free(comp, zstrm);
}

/* change max_strm limit */
static bool zcomp_strm_multi_set_max_streams(struct zcomp *comp, int num_strm)
{
	struct zcomp_strm_multi *zs = comp->stream;
	struct zcomp_strm *zstrm;

	spin_lock(&zs->strm_lock);
	zs->max_strm = num_strm;
	/*
	 * if user has lowered the limit and there are idle streams,
	 * immediately free as much streams (and memory) as we can.
	 */
	while (zs->avail_strm > num_strm && !list_empty(&zs->idle_strm)) {
		zstrm = list_entry(zs->idle_strm.next,
				struct zcomp_strm, list);
		list_del(&zstrm->list);
		zcomp_strm_free(comp, zstrm);
		zs->avail_strm--;
	}
	spin_unlock(&zs->strm_lock);
	return true;
}

static void zcomp_strm_multi_destroy(struct zcomp *comp)
{
	struct zcomp_strm_multi *zs = comp->stream;
	struct zcomp_strm *zstrm;

	while (!list_empty(&zs->idle_strm)) {
		zstrm = list_entry(zs->idle_strm.next,
				struct zcomp_strm, list);
		list_del(&zstrm->list);
		zcomp_strm_free(comp, zstrm);
	}
	kfree(zs);
}

static int zcomp_strm_multi_create(struct zcomp *comp, int max_strm)
{
	struct zcomp_strm *zstrm;
	struct zcomp_strm_multi *zs;

	comp->destroy = zcomp_strm_multi_destroy;
	comp->strm_find = zcomp_strm_multi_find;
	comp->strm_release = zcomp_strm_multi_release;
	comp->set_max_streams = zcomp_strm_multi_set_max_streams;
	zs = kmalloc(sizeof(struct zcomp_strm_multi), GFP_KERNEL);
	if (!zs)
		return -ENOMEM;

	comp->stream = zs;
	spin_lock_init(&zs->strm_lock);
	INIT_LIST_HEAD(&zs->idle_strm);
	init_waitqueue_head(&zs->strm_wait);
	zs->max_strm = max_strm;
	zs->avail_strm = 1;

	zstrm = zcomp_strm_alloc(comp);
	if (!zstrm) {
		kfree(zs);
		return -ENOMEM;
	}
	list_add(&zstrm->list, &zs->idle_strm);
	return 0;
}

static struct zcomp_strm *zcomp_strm_single_find(struct zcomp *comp)
{
	struct zcomp_strm_single *zs = comp->stream;
	mutex_lock(&zs->strm_lock);
	return zs->zstrm;
}

static void zcomp_strm_single_release(struct zcomp *comp,
		struct zcomp_strm *zstrm)
{
	struct zcomp_strm_single *zs = comp->stream;
	mutex_unlock(&zs->strm_lock);
}

static bool zcomp_strm_single_set_max_streams(struct zcomp *comp, int num_strm)
{
	/* zcomp_strm_single support only max_comp_streams == 1 */
	return false;
}

static void zcomp_strm_single_destroy(struct zcomp *comp)
{
	struct zcomp_strm_single *zs = comp->stream;
	zcomp_strm_free(comp, zs->zstrm);
	kfree(zs);
}

static int zcomp_strm_single_create(struct zcomp *comp)
{
	struct zcomp_strm_single *zs;

	comp->destroy = zcomp_strm_single_destroy;
	comp->strm_find = zcomp_strm_single_find;
	comp->strm_release = zcomp_strm_single_release;
	comp->set_max_streams = zcomp_strm_single_set_max_streams;
	zs = kmalloc(sizeof(struct zcomp_strm_single), GFP_KERNEL);
	if (!zs)
		return -ENOMEM;

	comp->stream = zs;
	mutex_init(&zs->strm_lock);
	zs->zstrm = zcomp_strm_alloc(comp);
	if (!zs->zstrm) {
		kfree(zs);
		return -ENOMEM;
	}
	return 0;
}

/* show available compressors */
ssize_t zcomp_available_show(const char *comp, char *buf)
{
	ssize_t sz = 0;
	int i = 0;

	while (backends[i]) {
		if (sysfs_streq(comp, backends[i]->name))
			sz += scnprintf(buf + sz, PAGE_SIZE - sz - 2,
					"[%s] ", backends[i]->name);
		else
			sz += scnprintf(buf + sz, PAGE_SIZE - sz - 2,
					"%s ", backends[i]->name);
		i++;
	}
	sz += scnprintf(buf + sz, PAGE_SIZE - sz, "\n");
	return sz;
}

bool zcomp_set_max_streams(struct zcomp *comp, int num_strm)
{
	return comp->set_max_streams(comp, num_strm);
}

struct zcomp_strm *zcomp_strm_find(struct zcomp *comp)
{
	return comp->strm_find(comp);
}

void zcomp_strm_release(struct zcomp *comp, struct zcomp_strm *zstrm)
{
	comp->strm_release(comp, zstrm);
}

int zcomp_compress(struct zcomp *comp, struct zcomp_strm *zstrm,
		const unsigned char *src, size_t *dst_len)
{
	return comp->backend->compress(src, zstrm->buffer, dst_len,
			zstrm->private);
}

int zcomp_decompress(struct zcomp *comp, const unsigned char *src,
		size_t src_len, unsigned char *dst)
{
	return comp->backend->decompress(src, src_len, dst);
}

void zcomp_destroy(struct zcomp *comp)
{
	comp->destroy(comp);
	kfree(comp);
}

/*
 * search available compressors for requested algorithm.
 * allocate new zcomp and initialize it. return compressing
 * backend pointer or ERR_PTR if things went bad. ERR_PTR(-EINVAL)
 * if requested algorithm is not supported, ERR_PTR(-ENOMEM) in
 * case of allocation error, or any other error potentially
 * returned by functions zcomp_strm_{multi,single}_create.
 */
struct zcomp *zcomp_create(const char *compress, int max_strm)
{
	struct zcomp *comp;
	struct zcomp_backend *backend;
	int error;

	backend = find_backend(compress);
	if (!backend)
		return ERR_PTR(-EINVAL);

	comp = kzalloc(sizeof(struct zcomp), GFP_KERNEL);
	if (!comp)
		return ERR_PTR(-ENOMEM);

	comp->backend = backend;
	if (max_strm > 1)
		error = zcomp_strm_multi_create(comp, max_strm);
	else
		error = zcomp_strm_single_create(comp);
	if (error) {
		kfree(comp);
		return ERR_PTR(error);
	}
	return comp;
}
