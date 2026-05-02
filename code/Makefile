# 目标驱动模块名
obj-m := dream.o

# dream.o 由哪些目标文件链接而成，这里只有一个 dream.c，所以直接写 dream.o 即可
# 你的所有 .h 文件会在编译时自动被 dream.c 包含，无需在此列出

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
