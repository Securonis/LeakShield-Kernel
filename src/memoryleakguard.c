#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stacktrace.h>
#include <linux/vmalloc.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("root0emir");
MODULE_DESCRIPTION("MemoryLeakGuard - Memory Leak Detection and Prevention");
MODULE_VERSION("1.0");

#define MLG_STACK_ENTRIES 32
#define MLG_HASH_BITS 12
#define MLG_MAX_TRACKED 10000
#define MLG_LEAK_THRESHOLD (5 * 60) /* 5 minutes in seconds */

/* Memory allocation tracking structure */
struct mem_track {
    struct rb_node node;
    struct hlist_node hash_node;
    unsigned long addr;
    size_t size;
    pid_t pid;
    char comm[TASK_COMM_LEN];
    unsigned long stack_entries[MLG_STACK_ENTRIES];
    unsigned int nr_entries;
    ktime_t alloc_time;
    unsigned int access_count;
    bool is_leaked;
};

/* Global variables */
static DEFINE_HASHTABLE(track_hash, MLG_HASH_BITS);
static struct rb_root track_tree = RB_ROOT;
static DEFINE_SPINLOCK(track_lock);
static atomic_t total_allocs = ATOMIC_INIT(0);
static atomic_t total_leaks = ATOMIC_INIT(0);

/* Find tracked memory in tree */
static struct mem_track *find_track(unsigned long addr) {
    struct rb_node *node = track_tree.rb_node;
    
    while (node) {
        struct mem_track *track = container_of(node, struct mem_track, node);
        
        if (addr < track->addr)
            node = node->rb_left;
        else if (addr >= track->addr + track->size)
            node = node->rb_right;
        else
            return track;
    }
    return NULL;
}

/* Insert new tracked memory */
static int insert_track(struct mem_track *new) {
    struct rb_node **link = &track_tree.rb_node;
    struct rb_node *parent = NULL;
    
    while (*link) {
        struct mem_track *track;
        parent = *link;
        track = container_of(parent, struct mem_track, node);
        
        if (new->addr < track->addr)
            link = &(*link)->rb_left;
        else if (new->addr >= track->addr + track->size)
            link = &(*link)->rb_right;
        else
            return -EEXIST;
    }
    
    rb_link_node(&new->node, parent, link);
    rb_insert_color(&new->node, &track_tree);
    hash_add(track_hash, &new->hash_node, new->addr);
    atomic_inc(&total_allocs);
    return 0;
}

/* Save stack trace */
static void save_stack_trace(struct mem_track *track) {
    struct stack_trace trace = {
        .nr_entries = 0,
        .entries = track->stack_entries,
        .max_entries = MLG_STACK_ENTRIES,
        .skip = 2
    };
    
    save_stack_trace(&trace);
    track->nr_entries = trace.nr_entries;
}

/* Check for memory leaks */
static void check_leaks(void) {
    struct rb_node *node;
    unsigned long flags;
    ktime_t now = ktime_get_real();
    
    spin_lock_irqsave(&track_lock, flags);
    for (node = rb_first(&track_tree); node; node = rb_next(node)) {
        struct mem_track *track = container_of(node, struct mem_track, node);
        s64 diff = ktime_to_seconds(ktime_sub(now, track->alloc_time));
        
        if (!track->is_leaked && diff > MLG_LEAK_THRESHOLD && track->access_count == 0) {
            track->is_leaked = true;
            atomic_inc(&total_leaks);
            printk(KERN_WARNING "MLG: Potential memory leak detected at %lx (size: %zu, pid: %d, comm: %s)\n",
                   track->addr, track->size, track->pid, track->comm);
        }
    }
    spin_unlock_irqrestore(&track_lock, flags);
}

/* Track memory allocation */
static void track_alloc(unsigned long addr, size_t size) {
    struct mem_track *track;
    unsigned long flags;
    
    if (atomic_read(&total_allocs) >= MLG_MAX_TRACKED)
        return;
        
    track = kzalloc(sizeof(*track), GFP_ATOMIC);
    if (!track)
        return;
        
    track->addr = addr;
    track->size = size;
    track->pid = current->pid;
    memcpy(track->comm, current->comm, TASK_COMM_LEN);
    track->alloc_time = ktime_get_real();
    save_stack_trace(track);
    
    spin_lock_irqsave(&track_lock, flags);
    if (insert_track(track))
        kfree(track);
    spin_unlock_irqrestore(&track_lock, flags);
}

/* Track memory access */
static void track_access(unsigned long addr) {
    struct mem_track *track;
    unsigned long flags;
    
    spin_lock_irqsave(&track_lock, flags);
    track = find_track(addr);
    if (track)
        track->access_count++;
    spin_unlock_irqrestore(&track_lock, flags);
}

/* Track memory free */
static void track_free(unsigned long addr) {
    struct mem_track *track;
    unsigned long flags;
    
    spin_lock_irqsave(&track_lock, flags);
    track = find_track(addr);
    if (track) {
        hash_del(&track->hash_node);
        rb_erase(&track->node, &track_tree);
        if (track->is_leaked)
            atomic_dec(&total_leaks);
        atomic_dec(&total_allocs);
        kfree(track);
    }
    spin_unlock_irqrestore(&track_lock, flags);
}

/* Proc interface */
static void print_stack_trace(struct seq_file *m, struct mem_track *track) {
    char symbol[KSYM_SYMBOL_LEN];
    unsigned int i;
    
    for (i = 0; i < track->nr_entries; i++) {
        sprint_symbol(symbol, track->stack_entries[i]);
        seq_printf(m, "  %s\n", symbol);
    }
}

static int memoryleakguard_proc_show(struct seq_file *m, void *v) {
    struct rb_node *node;
    unsigned long flags;
    
    seq_printf(m, "MemoryLeakGuard Statistics:\n");
    seq_printf(m, "Total tracked allocations: %d\n", atomic_read(&total_allocs));
    seq_printf(m, "Total potential leaks: %d\n", atomic_read(&total_leaks));
    
    spin_lock_irqsave(&track_lock, flags);
    for (node = rb_first(&track_tree); node; node = rb_next(node)) {
        struct mem_track *track = container_of(node, struct mem_track, node);
        if (track->is_leaked) {
            seq_printf(m, "\nLeak at %lx (size: %zu bytes)\n", track->addr, track->size);
            seq_printf(m, "Process: %s (PID: %d)\n", track->comm, track->pid);
            seq_printf(m, "Allocation time: %lld seconds ago\n",
                      ktime_to_seconds(ktime_sub(ktime_get_real(), track->alloc_time)));
            seq_printf(m, "Access count: %u\n", track->access_count);
            seq_printf(m, "Stack trace:\n");
            print_stack_trace(m, track);
        }
    }
    spin_unlock_irqrestore(&track_lock, flags);
    
    return 0;
}

static int memoryleakguard_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, memoryleakguard_proc_show, NULL);
}

static const struct proc_ops memoryleakguard_proc_fops = {
    .proc_open = memoryleakguard_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* Kretprobe handlers for kmalloc */
static int kmalloc_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct kmalloc_data {
        size_t size;
    } *data;
    
    data = (struct kmalloc_data *)ri->data;
    data->size = regs->di; /* size argument */
    return 0;
}

static int kmalloc_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct kmalloc_data *data = (struct kmalloc_data *)ri->data;
    unsigned long addr = regs_return_value(regs);
    
    if (addr)
        track_alloc(addr, data->size);
    return 0;
}

static struct kretprobe kmalloc_probe = {
    .handler = kmalloc_ret_handler,
    .entry_handler = kmalloc_entry_handler,
    .data_size = sizeof(struct kmalloc_data),
    .maxactive = 20,
};

static int __init memoryleakguard_init(void) {
    int ret;
    
    /* Register kretprobe */
    kmalloc_probe.kp.symbol_name = "kmalloc";
    ret = register_kretprobe(&kmalloc_probe);
    if (ret < 0) {
        printk(KERN_ERR "MLG: Failed to register kmalloc probe\n");
        return ret;
    }
    
    /* Create proc entry */
    if (!proc_create("memoryleakguard", 0440, NULL, &memoryleakguard_proc_fops)) {
        unregister_kretprobe(&kmalloc_probe);
        return -ENOMEM;
    }
    
    printk(KERN_INFO "MLG: Memory leak detection initialized\n");
    return 0;
}

static void __exit memoryleakguard_exit(void) {
    struct rb_node *node, *next;
    
    /* Unregister kretprobe */
    unregister_kretprobe(&kmalloc_probe);
    
    /* Remove proc entry */
    remove_proc_entry("memoryleakguard", NULL);
    
    /* Clean up tracking data */
    spin_lock(&track_lock);
    for (node = rb_first(&track_tree); node; node = next) {
        struct mem_track *track = container_of(node, struct mem_track, node);
        next = rb_next(node);
        hash_del(&track->hash_node);
        rb_erase(node, &track_tree);
        kfree(track);
    }
    spin_unlock(&track_lock);
    
    printk(KERN_INFO "MLG: Memory leak detection unloaded\n");
}

module_init(memoryleakguard_init);
module_exit(memoryleakguard_exit); 