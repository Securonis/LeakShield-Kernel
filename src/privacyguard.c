#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/random.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("root0emir");
MODULE_DESCRIPTION("Privacy Guard - Memory and Data Protection");
MODULE_VERSION("1.0");

#define PG_SALT_SIZE 16
#define PG_KEY_SIZE 32
#define PG_BLOCK_SIZE 16
#define MAX_PROTECTED_REGIONS 1024

/* Protected memory region structure */
struct protected_region {
    struct rb_node node;
    unsigned long start;
    unsigned long size;
    u8 key[PG_KEY_SIZE];
    u8 salt[PG_SALT_SIZE];
    pid_t owner_pid;
    kuid_t owner_uid;
    unsigned int flags;
    bool is_encrypted;
};

/* Global variables */
static struct rb_root regions_root = RB_ROOT;
static DEFINE_SPINLOCK(regions_lock);
static struct crypto_skcipher *tfm;
static char *zero_page;

/* Find protected region containing address */
static struct protected_region *find_region(unsigned long addr) {
    struct rb_node *node = regions_root.rb_node;
    
    while (node) {
        struct protected_region *region = container_of(node, struct protected_region, node);
        
        if (addr < region->start)
            node = node->rb_left;
        else if (addr >= region->start + region->size)
            node = node->rb_right;
        else
            return region;
    }
    return NULL;
}

/* Insert new protected region */
static int insert_region(struct protected_region *new) {
    struct rb_node **link = &regions_root.rb_node;
    struct rb_node *parent = NULL;
    
    while (*link) {
        struct protected_region *region;
        parent = *link;
        region = container_of(parent, struct protected_region, node);
        
        if (new->start < region->start)
            link = &(*link)->rb_left;
        else if (new->start >= region->start + region->size)
            link = &(*link)->rb_right;
        else
            return -EEXIST;
    }
    
    rb_link_node(&new->node, parent, link);
    rb_insert_color(&new->node, &regions_root);
    return 0;
}

/* Encrypt memory region */
static int encrypt_region(struct protected_region *region) {
    struct scatterlist sg;
    SKCIPHER_REQUEST_ON_STACK(req, tfm);
    u8 *temp_buf;
    int ret;

    if (region->is_encrypted)
        return 0;

    temp_buf = vmalloc(region->size);
    if (!temp_buf)
        return -ENOMEM;

    if (copy_from_user(temp_buf, (void __user *)region->start, region->size)) {
        vfree(temp_buf);
        return -EFAULT;
    }

    sg_init_one(&sg, temp_buf, region->size);
    skcipher_request_set_tfm(req, tfm);
    skcipher_request_set_crypt(req, &sg, &sg, region->size, region->key);

    ret = crypto_skcipher_encrypt(req);
    if (ret == 0) {
        if (copy_to_user((void __user *)region->start, temp_buf, region->size))
            ret = -EFAULT;
        else
            region->is_encrypted = true;
    }

    vfree(temp_buf);
    skcipher_request_zero(req);
    return ret;
}

/* Decrypt memory region */
static int decrypt_region(struct protected_region *region) {
    struct scatterlist sg;
    SKCIPHER_REQUEST_ON_STACK(req, tfm);
    u8 *temp_buf;
    int ret;

    if (!region->is_encrypted)
        return 0;

    temp_buf = vmalloc(region->size);
    if (!temp_buf)
        return -ENOMEM;

    if (copy_from_user(temp_buf, (void __user *)region->start, region->size)) {
        vfree(temp_buf);
        return -EFAULT;
    }

    sg_init_one(&sg, temp_buf, region->size);
    skcipher_request_set_tfm(req, tfm);
    skcipher_request_set_crypt(req, &sg, &sg, region->size, region->key);

    ret = crypto_skcipher_decrypt(req);
    if (ret == 0) {
        if (copy_to_user((void __user *)region->start, temp_buf, region->size))
            ret = -EFAULT;
        else
            region->is_encrypted = false;
    }

    vfree(temp_buf);
    skcipher_request_zero(req);
    return ret;
}

/* Memory access handler */
static bool handle_memory_access(unsigned long addr, unsigned int flags) {
    struct protected_region *region;
    bool allowed = true;
    unsigned long irq_flags;
    
    spin_lock_irqsave(&regions_lock, irq_flags);
    region = find_region(addr);
    
    if (region) {
        /* Check access permissions */
        if (region->owner_uid.val != current_uid().val) {
            /* Zero out the memory on unauthorized access */
            if (zero_page && copy_to_user((void __user *)addr, zero_page, PAGE_SIZE) == 0) {
                printk(KERN_WARNING "PrivacyGuard: Unauthorized access blocked at %lx\n", addr);
            }
            allowed = false;
        } else if (region->is_encrypted) {
            /* Decrypt for authorized access */
            decrypt_region(region);
        }
    }
    spin_unlock_irqrestore(&regions_lock, irq_flags);
    
    return allowed;
}

/* Protect memory region */
static long protect_memory_region(unsigned long start, size_t size) {
    struct protected_region *region;
    unsigned long irq_flags;
    int ret = 0;
    
    if (!size || !start)
        return -EINVAL;
        
    region = kzalloc(sizeof(*region), GFP_KERNEL);
    if (!region)
        return -ENOMEM;
        
    region->start = start;
    region->size = size;
    region->owner_pid = current->pid;
    region->owner_uid = current_uid();
    get_random_bytes(region->key, PG_KEY_SIZE);
    get_random_bytes(region->salt, PG_SALT_SIZE);
    
    spin_lock_irqsave(&regions_lock, irq_flags);
    ret = insert_region(region);
    if (ret == 0) {
        ret = encrypt_region(region);
        if (ret) {
            rb_erase(&region->node, &regions_root);
            kfree(region);
        }
    } else {
        kfree(region);
    }
    spin_unlock_irqrestore(&regions_lock, irq_flags);
    
    return ret;
}

/* Proc interface */
static int privacyguard_proc_show(struct seq_file *m, void *v) {
    struct rb_node *node;
    unsigned long flags;
    
    seq_printf(m, "Protected Memory Regions:\n");
    seq_printf(m, "Start\t\tSize\t\tOwner\t\tEncrypted\n");
    
    spin_lock_irqsave(&regions_lock, flags);
    for (node = rb_first(&regions_root); node; node = rb_next(node)) {
        struct protected_region *region = container_of(node, struct protected_region, node);
        seq_printf(m, "%lx\t%lx\t%u\t\t%s\n",
                  region->start, region->size,
                  region->owner_uid.val,
                  region->is_encrypted ? "Yes" : "No");
    }
    spin_unlock_irqrestore(&regions_lock, flags);
    
    return 0;
}

static int privacyguard_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, privacyguard_proc_show, NULL);
}

static const struct proc_ops privacyguard_proc_fops = {
    .proc_open = privacyguard_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init privacyguard_init(void) {
    /* Initialize crypto */
    tfm = crypto_alloc_skcipher("aes", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "PrivacyGuard: Failed to allocate cipher\n");
        return PTR_ERR(tfm);
    }
    
    /* Allocate zero page */
    zero_page = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!zero_page) {
        crypto_free_skcipher(tfm);
        return -ENOMEM;
    }
    
    /* Create proc entry */
    if (!proc_create("privacyguard", 0440, NULL, &privacyguard_proc_fops)) {
        crypto_free_skcipher(tfm);
        kfree(zero_page);
        return -ENOMEM;
    }
    
    printk(KERN_INFO "PrivacyGuard: Privacy protection initialized\n");
    return 0;
}

static void __exit privacyguard_exit(void) {
    struct rb_node *node, *next;
    
    /* Clean up proc entry */
    remove_proc_entry("privacyguard", NULL);
    
    /* Free crypto resources */
    crypto_free_skcipher(tfm);
    
    /* Free zero page */
    kfree(zero_page);
    
    /* Clean up protected regions */
    spin_lock(&regions_lock);
    for (node = rb_first(&regions_root); node; node = next) {
        struct protected_region *region = container_of(node, struct protected_region, node);
        next = rb_next(node);
        decrypt_region(region);
        rb_erase(node, &regions_root);
        kfree(region);
    }
    spin_unlock(&regions_lock);
    
    printk(KERN_INFO "PrivacyGuard: Privacy protection unloaded\n");
}

module_init(privacyguard_init);
module_exit(privacyguard_exit); 