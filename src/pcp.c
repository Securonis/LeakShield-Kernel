#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/bpf.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/hash.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("root0emir");
MODULE_DESCRIPTION("Process Credential Protection");
MODULE_VERSION("1.0");

struct pcp_entry {
    struct rb_node node;
    pid_t pid;
    uid_t original_uid;
    unsigned long timestamp;
    unsigned int flags;
};

static struct rb_root pcp_tree = RB_ROOT;
static DEFINE_SPINLOCK(pcp_lock);

/* Hash function for PID to reduce collision */
static inline unsigned long pcp_hash(pid_t pid) {
    return hash_64(pid, 16);
}

/* Find entry in red-black tree */
static struct pcp_entry *pcp_find(pid_t pid) {
    struct rb_node *node = pcp_tree.rb_node;
    unsigned long hash = pcp_hash(pid);

    while (node) {
        struct pcp_entry *entry = container_of(node, struct pcp_entry, node);
        if (hash < pcp_hash(entry->pid))
            node = node->rb_left;
        else if (hash > pcp_hash(entry->pid))
            node = node->rb_right;
        else
            return entry;
    }
    return NULL;
}

/* Insert new entry into red-black tree */
static int pcp_insert(struct pcp_entry *new) {
    struct rb_node **node = &pcp_tree.rb_node;
    struct rb_node *parent = NULL;
    unsigned long hash = pcp_hash(new->pid);

    while (*node) {
        struct pcp_entry *entry = container_of(*node, struct pcp_entry, node);
        parent = *node;
        
        if (hash < pcp_hash(entry->pid))
            node = &(*node)->rb_left;
        else if (hash > pcp_hash(entry->pid))
            node = &(*node)->rb_right;
        else
            return -EEXIST;
    }

    rb_link_node(&new->node, parent, node);
    rb_insert_color(&new->node, &pcp_tree);
    return 0;
}

/* Check if credential change is allowed */
static int pcp_check_creds(void) {
    struct pcp_entry *entry;
    struct task_struct *task = current;
    int ret = 0;

    if (!task)
        return 0;

    spin_lock(&pcp_lock);
    entry = pcp_find(task->pid);
    
    if (entry) {
        /* Check for suspicious credential changes */
        if (entry->original_uid != task->cred->uid.val) {
            if (entry->flags & 0x1) { /* Protected process */
                printk(KERN_WARNING "PCP: Blocked suspicious credential change for PID %d\n", task->pid);
                ret = -EPERM;
            }
        }
    } else {
        /* New process - create entry */
        entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
        if (entry) {
            entry->pid = task->pid;
            entry->original_uid = task->cred->uid.val;
            entry->timestamp = jiffies;
            entry->flags = 0;
            
            if (pcp_insert(entry) < 0)
                kfree(entry);
        }
    }
    spin_unlock(&pcp_lock);
    
    return ret;
}

/* Clean up expired entries */
static void pcp_cleanup_entries(void) {
    struct rb_node *node;
    unsigned long expire_time = jiffies - HZ * 3600; /* 1 hour */

    spin_lock(&pcp_lock);
    for (node = rb_first(&pcp_tree); node; node = rb_next(node)) {
        struct pcp_entry *entry = container_of(node, struct pcp_entry, node);
        if (entry->timestamp < expire_time) {
            rb_erase(&entry->node, &pcp_tree);
            kfree(entry);
        }
    }
    spin_unlock(&pcp_lock);
}

static int __init pcp_init(void) {
    printk(KERN_INFO "PCP: Process Credential Protection initialized\n");
    security_hook_list_add((void*)pcp_check_creds, LSM_HOOK_CRED_PREPARE);
    return 0;
}

static void __exit pcp_exit(void) {
    struct rb_node *node;
    struct pcp_entry *entry;

    /* Clean up all entries */
    while ((node = rb_first(&pcp_tree))) {
        entry = container_of(node, struct pcp_entry, node);
        rb_erase(node, &pcp_tree);
        kfree(entry);
    }
    
    printk(KERN_INFO "PCP: Process Credential Protection unloaded\n");
}

module_init(pcp_init);
module_exit(pcp_exit); 