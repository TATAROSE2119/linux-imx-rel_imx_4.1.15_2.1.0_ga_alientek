# drivers/block/zram/zstd/Makefile

obj-$(CONFIG_ZRAM_ZSTD_COMPRESS) += zstd_compressor.o

zstd_compressor-y := zstd_crypto_module.o \
                     compress.o \
                     decompress.o \
                     entropy_common.o \
                     fse_compress.o \
                     fse_decompress.o \
                     huf_compress.o \
                     huf_decompress.o \
                     zstd_common.o \
                     xxhash.o