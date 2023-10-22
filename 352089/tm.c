/**
 * @file   tm.c
 * @author [...]
 *
 * @section LICENSE
 *
 * [...]
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
 **/

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#ifdef __STDC_NO_ATOMICS__
#error Current C11 compiler does not support atomic operations
#endif

// External headers

// Internal headers
#include "tm.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <stdint.h>
#include "macros.h"

struct version_lock
{
    atomic_bool write_lock;
    atomic_uint_fast64_t version;
};

struct segment
{
    struct segment *prev;
    struct segment *next;
    size_t size;
    struct version_lock *locks;
    atomic_bool alloc_lock;
};

struct region
{
    atomic_uint_fast64_t global_version;
    struct segment *segments;
    size_t align;
};

struct map_value
{
    void *key;
    void *value;
    size_t size;
};

struct map
{
    struct map_value *pairs;
    uint64_t size;
    uint64_t capacity;
};

void map_init(struct map *map)
{
    map->capacity = 10;
    map->pairs = (struct map_value *)malloc(sizeof(struct map_value) * map->capacity);
    map->size = 0;
}

void map_destroy(struct map *map)
{
    free(map->pairs);
}

void *map_get(struct map *map, void *key, size_t *size)
{
    for (uint64_t i = 0; i < map->size; i++)
    {
        if (map->pairs[i].key == key)
        {
            size = map->pairs[i].size;
            return map->pairs[i].value;
        }
    }

    return NULL;
}

void map_set(struct map *map, void *key, void *value, size_t size)
{
    if (map->size == map->capacity)
    {
        map->capacity *= 2;
        map->pairs = (struct map_value *)realloc(map->pairs, map->capacity);
    }

    map->pairs[map->size].key = key;
    map->pairs[map->size].value = value;
    map->pairs[map->size].size = size;
    map->size++;
}

struct transaction
{
    uint64_t read_version;
    uint64_t write_version;
    struct map read_set;
    struct map write_set;
    bool is_read_only;
};

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
 **/
shared_t tm_create(size_t size, size_t align)
{
    struct region *region = (struct region *)malloc(sizeof(struct region));
    if (unlikely(!region))
    {
        return invalid_shared;
    }
    region->align = align;

    // We allocate the shared memory buffer such that its words are correctly
    // aligned.
    if (unlikely(posix_memalign((void **)&region->segments, align, sizeof(struct segment) + size) != 0))
    { // Allocation failed
        free(region);

        return invalid_shared;
    }

    region->segments->locks = (struct version_lock *)malloc(sizeof(struct version_lock) * size / align);
    if (unlikely(!region->segments->locks))
    {
        free(region->segments);
        free(region);

        return invalid_shared;
    }

    return invalid_shared;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
 **/
void tm_destroy(shared_t shared)
{
    struct region *region = (struct region *)shared;
    while (region->segments)
    {
        struct segment *next = region->segments->next;
        free(region->segments->locks);
        free(region->segments);
        region->segments = next;
    }
    free(region);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
 **/
void *tm_start(shared_t shared)
{
    struct region *region = (struct region *)shared;
    return (void *)((uintptr_t)region->segments + sizeof(struct segment));
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
 **/
size_t tm_size(shared_t unused(shared))
{
    struct region *region = (struct region *)shared;
    return region->segments->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
 **/
size_t tm_align(shared_t unused(shared))
{
    struct region *region = (struct region *)shared;
    return region->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
 **/
tx_t tm_begin(shared_t shared, bool is_ro)
{
    struct region *region = (struct region *)shared;
    struct transaction *t = (struct transaction *)malloc(sizeof(struct transaction));
    t->is_read_only = is_ro;
    map_init(&t->read_set);
    map_init(&t->write_set);
    t->read_version = region->global_version;

    return (tx_t)t;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
 **/
bool tm_end(shared_t unused(shared), tx_t tx)
{
    struct transaction *t = (struct transaction *)tx;
    // TODO: tm_end(shared_t, tx_t)
    // Implement execution of transaction
    map_destroy(&t->read_set);
    map_destroy(&t->write_set);
    free(t);

    return false;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
 **/
bool tm_read(shared_t shared, tx_t tx, void const *source, size_t size, void *target)
{
    struct transaction *t = (struct transaction *)tx;
    struct region *region = (struct region *)shared;

    struct segment *current = region->segments;
    while (current != NULL)
    {
        uintptr_t segment_start = (uintptr_t)current + sizeof(struct segment);
        if (source >= segment_start && source < segment_start + current->size)
        {
            struct version_lock *lock = &current->locks[(uint64_t)(source - segment_start) / region->align];
            // Abort transaction if the object was marked for deallocation (alloc_lock == true)
            // or if the object is currently being writte (write_lock == true)
            // or if the lock version is greater than the transaction read version (meaning that the object was update in the meantime)
            if (atomic_load(&current->alloc_lock) || atomic_load(&lock->write_lock) || atomic_load(&lock->version) > t->read_version)
            {
                return false;
            }

            break;
        }
    }

    // means there's no segment containing the source address in the shared region
    if (current == NULL)
    {
        return false;
    }

    map_set(&t->read_set, source, target, size);
    return true;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
 **/
bool tm_write(shared_t shared, tx_t tx, void const *source, size_t size, void *target)
{
    struct transaction *t = (struct transaction *)tx;
    struct region *region = (struct region *)shared;

    struct segment *current = region->segments;
    while (current != NULL)
    {
        uintptr_t segment_start = (uintptr_t)current + sizeof(struct segment);
        if (source >= segment_start && source < segment_start + current->size)
        {
            struct version_lock *lock = &current->locks[(uint64_t)(source - segment_start) / region->align];
            // Abort transaction if the object was marked for deallocation (alloc_lock == true)
            // or if the object is currently being writte (write_lock == true)
            // or if the lock version is greater than the transaction read version (meaning that the object was update in the meantime)
            if (atomic_load(&current->alloc_lock) || atomic_load(&lock->write_lock) || atomic_load(&lock->version) > t->read_version)
            {
                return false;
            }

            break;
        }
    }

    // means there's no segment containing the source address in the shared region
    if (current == NULL)
    {
        return false;
    }

    map_set(&t->write_set, source, target, size);
    return true;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
 **/
alloc_t tm_alloc(shared_t unused(shared), tx_t unused(tx), size_t unused(size), void **unused(target))
{
    // TODO: tm_alloc(shared_t, tx_t, size_t, void**)
    return abort_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
 **/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void *unused(target))
{
    // TODO: tm_free(shared_t, tx_t, void*)
    return false;
}
