/*
 * zstd_crypto_module.c - Linux Kernel Crypto API 压缩模块
 *
 * 本模块将 Zstandard (zstd) 压缩算法注册到 Linux 内核加密框架中，
 * 使内核其他子系统（如 squashfs, ubifs, f2fs 等）可以通过 Crypto API
 * 透明地使用 zstd 压缩/解压功能。
 *
 * 目标内核版本: Linux 4.1.x (ARM 交叉编译)
 * 许可证: GPL v2
 */

/* ===== 内核头文件 ===== */
#include <linux/crypto.h>   /* Crypto API: crypto_register_alg, crypto_tfm 等 */
#include <linux/err.h>      /* 错误码: ENOMEM, EINVAL 等 */
#include <linux/kernel.h>   /* 内核基础: printk 等 */
#include <linux/module.h>   /* 模块框架: module_init, module_exit, MODULE_* */
#include <linux/slab.h>     /* 内存分配: kmalloc, kfree (备用) */
#include <linux/vmalloc.h>  /* 虚拟内存: vmalloc, vfree (用于大块连续虚拟内存) */

/* ===== zstd 库头文件 ===== */
#include "zstd.h"           /* zstd 公共 API: ZSTD_compressCCtx, ZSTD_decompressDCtx 等 */


/**
 * struct zstd_ctx - zstd 压缩/解压的私有上下文
 * @cctx: 指向 ZSTD_CCtx (压缩上下文) 工作空间的指针
 * @dctx: 指向 ZSTD_DCtx (解压上下文) 工作空间的指针
 *
 * 每次压缩/解压操作都需要一个上下文来保存状态。
 * 使用 vmalloc 分配工作空间，ZSTD_initCCtx/ZSTD_initDCtx 在其中
 * 原地 (in-place) 初始化上下文结构。
 */
struct zstd_ctx {
	void *cctx;	/* ZSTD 压缩上下文 */
	void *dctx;	/* ZSTD 解压上下文 */
};

/**
 * zstd_comp_init() - 初始化 zstd 压缩/解压上下文
 * @tfm: 内核 crypto 变换 (transform) 对象
 *
 * Crypto API 在创建压缩变换时调用此函数。
 * 负责:
 *   1. 计算压缩/解压上下文所需工作空间大小
 *   2. 分配工作空间内存
 *   3. 在工作空间中原地初始化 ZSTD 上下文
 *
 * 压缩级别固定为 1 (最快速度)，适用于内核场景。
 *
 * Return: 0 成功, -ENOMEM 内存不足
 */
static int zstd_comp_init(struct crypto_tfm *tfm)
{
	struct zstd_ctx *ctx = crypto_tfm_ctx(tfm);
	ZSTD_parameters params;
	size_t workspace_size;

	/* 获取默认压缩参数 (级别=1, 源大小未知=0, 无字典=0) */
	params = ZSTD_getParams(1, 0, 0);

	/* 计算压缩上下文所需工作空间大小 */
	workspace_size = ZSTD_CCtxWorkspaceBound(params.cParams);

	/* 分配压缩上下文工作空间 (vmalloc 保证物理不连续但虚拟连续) */
	ctx->cctx = vmalloc(workspace_size);
	if (!ctx->cctx)
		return -ENOMEM;

	/* 在工作空间中原地初始化压缩上下文 */
	ctx->cctx = ZSTD_initCCtx(ctx->cctx, workspace_size);
	if (!ctx->cctx) {
		vfree(ctx->cctx);
		return -ENOMEM;
	}

	/* 计算解压上下文所需工作空间大小 */
	workspace_size = ZSTD_DCtxWorkspaceBound();

	/* 分配解压上下文工作空间 */
	ctx->dctx = vmalloc(workspace_size);
	if (!ctx->dctx) {
		vfree(ctx->cctx);	/* 回滚: 释放已分配的压缩上下文 */
		return -ENOMEM;
	}

	/* 在工作空间中原地初始化解压上下文 */
	ctx->dctx = ZSTD_initDCtx(ctx->dctx, workspace_size);
	if (!ctx->dctx) {
		vfree(ctx->cctx);	/* 回滚: 释放压缩上下文 */
		vfree(ctx->dctx);	/* 回滚: 释放解压上下文工作空间 */
		return -ENOMEM;
	}

	return 0;
}

/**
 * zstd_comp_exit() - 释放 zstd 压缩/解压上下文资源
 * @tfm: 内核 crypto 变换对象
 *
 * Crypto API 在销毁压缩变换时调用此函数。
 * 释放初始化时分配的压缩和解压上下文工作空间。
 */
static void zstd_comp_exit(struct crypto_tfm *tfm)
{
	struct zstd_ctx *ctx = crypto_tfm_ctx(tfm);

	vfree(ctx->cctx);	/* 释放压缩上下文工作空间 */
	vfree(ctx->dctx);	/* 释放解压上下文工作空间 */
}

/**
 * zstd_compress_wrapper() - zstd 压缩回调函数
 * @tfm:  内核 crypto 变换对象
 * @src:  源数据缓冲区 (待压缩数据)
 * @slen: 源数据长度 (字节)
 * @dst:  目标缓冲区 (压缩后数据存放位置)
 * @dlen: [输入] 目标缓冲区容量 / [输出] 实际压缩后大小
 *
 * 此函数被 Crypto API 调用以执行 zstd 压缩。
 * 使用压缩级别 1 (最快)，根据实际源大小动态选择参数。
 *
 * Return: 0 成功, -EINVAL 压缩失败
 */
static int zstd_compress_wrapper(struct crypto_tfm *tfm, const u8 *src,
				 unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct zstd_ctx *ctx = crypto_tfm_ctx(tfm);
	/* 根据源数据大小动态获取最优压缩参数 */
	ZSTD_parameters params = ZSTD_getParams(1, slen, 0);
	size_t out;

	/* 执行 zstd 压缩 */
	out = ZSTD_compressCCtx(ctx->cctx, dst, *dlen, src, slen, params);

	/* 检查压缩是否出错 */
	if (ZSTD_isError(out))
		return -EINVAL;

	/* 将实际压缩后大小返回给调用者 */
	*dlen = out;
	return 0;
}

/**
 * zstd_decompress_wrapper() - zstd 解压回调函数
 * @tfm:  内核 crypto 变换对象
 * @src:  源数据缓冲区 (zstd 压缩数据)
 * @slen: 源数据长度 (字节)
 * @dst:  目标缓冲区 (解压后数据存放位置)
 * @dlen: [输入] 目标缓冲区容量 / [输出] 实际解压后大小
 *
 * 此函数被 Crypto API 调用以执行 zstd 解压。
 *
 * Return: 0 成功, -EINVAL 解压失败
 */
static int zstd_decompress_wrapper(struct crypto_tfm *tfm, const u8 *src,
				   unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct zstd_ctx *ctx = crypto_tfm_ctx(tfm);
	size_t out;

	/* 执行 zstd 解压 */
	out = ZSTD_decompressDCtx(ctx->dctx, dst, *dlen, src, slen);

	/* 检查解压是否出错 */
	if (ZSTD_isError(out))
		return -EINVAL;

	/* 将实际解压后大小返回给调用者 */
	*dlen = out;
	return 0;
}

/**
 * zstd_alg - zstd 算法注册结构体
 *
 * 定义 zstd 算法在内核 Crypto API 中的注册信息:
 *  - 算法名称: "zstd"
 *  - 优先级: 100 (较高，优先于其他同名算法)
 *  - 类型: CRYPTO_ALG_TYPE_COMPRESS (压缩算法)
 *  - 回调函数: init / exit / compress / decompress
 */
static struct crypto_alg zstd_alg = {
	.cra_name	= "zstd",		/* 算法名称 */
	.cra_driver_name = "zstd-generic",	/* 驱动名称 (通用实现) */
	.cra_priority	= 100,			/* 优先级 (越高越优先) */
	.cra_flags	= CRYPTO_ALG_TYPE_COMPRESS, /* 算法类型: 压缩 */
	.cra_ctxsize	= sizeof(struct zstd_ctx), /* 私有上下文大小 */
	.cra_module	= THIS_MODULE,		/* 所属模块 */
	.cra_init	= zstd_comp_init,	/* 初始化回调 */
	.cra_exit	= zstd_comp_exit,	/* 销毁回调 */
	.cra_u		= {
		.compress = {
			.coa_compress	= zstd_compress_wrapper, /* 压缩回调 */
			.coa_decompress	= zstd_decompress_wrapper, /* 解压回调 */
		}
	}
};

/**
 * zstd_module_init() - 模块加载入口
 *
 * 向内核 Crypto API 注册 zstd 压缩算法。
 * 注册后，内核可通过 crypto_alloc_comp("zstd", ...) 获取压缩变换。
 *
 * Return: 0 成功, 负值表示注册失败
 */
static int __init zstd_module_init(void)
{
    int ret = crypto_register_alg(&zstd_alg);
    if (ret)
        printk(KERN_ERR "Failed to register zstd algorithm: %d\n", ret);

    printk(KERN_INFO "zstd compression algorithm module loaded\n");
	return ret;
}

/**
 * zstd_module_exit() - 模块卸载入口
 *
 * 从内核 Crypto API 注销 zstd 压缩算法。
 */
static void __exit zstd_module_exit(void)
{
    crypto_unregister_alg(&zstd_alg);
}

/* ===== 模块注册宏 ===== */
module_init(zstd_module_init);	/* 指定模块加载函数 */
module_exit(zstd_module_exit);	/* 指定模块卸载函数 */

/* ===== 模块元信息 ===== */
MODULE_LICENSE("GPL");		/* 许可证: GPL (与内核保持一致) */
MODULE_DESCRIPTION("Zstd compression algorithm for Linux 4.1.X"); /* 模块描述 */