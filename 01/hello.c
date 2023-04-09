/**********************************************************
    > File Name: hello.c
    > Author:Edward
    > Mail:myue2019@gmail.com
    > Created Time: 2023年04月08日 星期六 20时17分51秒
 **********************************************************/
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int counter = 0;

SEC("xdp")
int hello(void *ctx){
	bpf_printk("Hello world %d", counter);
	counter++;
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

