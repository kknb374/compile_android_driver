obj-m += my_driver.o
# 注意：下面的 KDIR 由 GitHub Action 自动提供，不要修改
# KDIR := ...
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
