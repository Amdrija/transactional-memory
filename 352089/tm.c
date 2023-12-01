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

#include "macros.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct version_lock {
    atomic_bool write_lock;
    atomic_uint_fast64_t version;
};

struct segment {
    struct segment *prev;
    struct segment *next;
    size_t size;
    struct version_lock *locks;
    atomic_bool alloc_lock;
};

struct region {
    atomic_uint_fast64_t global_version;
    struct segment *segments;
    size_t align;
};

struct map_value {
    void *key;
    void *value;
    size_t size;
    struct segment *segment;
    struct version_lock *lock;
    void *previous_value;
};

struct map {
    struct map_value *pairs;
    uint64_t size;
    uint64_t capacity;
};

void map_init(struct map *map) {
    map->capacity = 20;
    map->pairs =
        (struct map_value *)malloc(sizeof(struct map_value) * map->capacity);
    map->size = 0;
}

void map_destroy(struct map *map) { free(map->pairs); }

struct map_value *map_get(struct map *map, void *key) {
    for (uint64_t i = 0; i < map->size; i++) {
        if (map->pairs[i].key == key) {

            return &map->pairs[i];
        }
    }

    return NULL;
}

uint64_t map_counts(struct map *map, void *key) {
    uint64_t counts = 0;
    for (uint64_t i = 0; i < map->size; i++) {
        if (map->pairs[i].key == key) {
            counts++;
        }
    }

    return counts;
}

// TODO: FIX THE REALLOCATION HERE, WE HAVE TO MODIFY THE MAP PROPERLY
void map_set(struct map *map, void *key, void *value, size_t size,
             struct segment *segment, struct version_lock *lock,
             void *previous_value) {
    if (map->size == map->capacity) {
        map->capacity *= 2;
        map->pairs = (struct map_value *)realloc(map->pairs, map->capacity);
    }

    map->pairs[map->size].key = key;
    map->pairs[map->size].value = value;
    map->pairs[map->size].size = size;
    map->pairs[map->size].segment = segment;
    map->pairs[map->size].lock = lock;
    map->pairs[map->size].previous_value = previous_value;

    map->size++;
}

struct transaction {
    struct map read_set;
    struct map write_set;
    uint64_t read_version;
    bool is_read_only;
};

/** Create (i.e. allocate + init) a new shared memory region, with one first
 *non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in
 *bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared
 *memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
 **/
shared_t tm_create(size_t size, size_t align) {
    printf("%lu: Creating region\n", pthread_self());
    struct region *region = (struct region *)malloc(sizeof(struct region));
    if (unlikely(!region)) {
        return invalid_shared;
    }
    region->align = align;
    atomic_store(&region->global_version, 0);

    // We allocate the shared memory buffer such that its words are correctly
    // aligned.
    if (unlikely(posix_memalign((void **)&region->segments, align,
                                sizeof(struct segment) + size) !=
                 0)) { // Allocation failed
        free(region);

        return invalid_shared;
    }

    printf("%lu: Alignment: %lu Size: %lu\n", pthread_self(), align, size);

    region->segments->next = NULL;
    region->segments->prev = NULL;
    region->segments->size = size;
    atomic_store(&region->segments->alloc_lock, false);
    region->segments->locks = (struct version_lock *)malloc(
        sizeof(struct version_lock) * size / align);
    if (unlikely(!region->segments->locks)) {
        free(region->segments);
        free(region);

        return invalid_shared;
    }

    printf("Created region\n");
    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
 **/
void tm_destroy(shared_t shared) {
    printf("%lu: Destroying region\n", pthread_self());
    struct region *region = (struct region *)shared;
    while (region->segments) {
        struct segment *next = region->segments->next;
        free(region->segments->locks);
        free(region->segments);
        region->segments = next;
    }
    free(region);
    printf("%lu: Destroyed region\n", pthread_self());
}

/** [thread-safe] Return the start address of the first allocated segment in the
 *shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
 **/
void *tm_start(shared_t shared) {
    struct region *region = (struct region *)shared;
    uintptr_t result = (uintptr_t)region->segments + sizeof(struct segment);
    printf("%lu: Started transaction: %p, %p, size: %lu\n", pthread_self(),
           region->segments, (void *)result, region->segments->size);
    return (void *)result;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of
 *the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
 **/
size_t tm_size(shared_t unused(shared)) {
    struct region *region = (struct region *)shared;
    return region->segments->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the
 *given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
 **/
size_t tm_align(shared_t unused(shared)) {
    struct region *region = (struct region *)shared;
    return region->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
 **/
tx_t tm_begin(shared_t unused(shared), bool is_ro) {
    struct region *region = (struct region *)shared;
    struct transaction *t =
        (struct transaction *)malloc(sizeof(struct transaction));
    t->is_read_only = is_ro;
    map_init(&t->read_set);
    map_init(&t->write_set);
    t->read_version = region->global_version;
    printf("%lu: Began transaction\n", pthread_self());
    return (tx_t)t;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
 **/
bool tm_end(shared_t shared, tx_t tx) {
    printf("%lu: Ending transaction\n", pthread_self());
    struct region *region = (struct region *)shared;
    struct transaction *t = (struct transaction *)tx;

    // Acquire locks for writing
    printf("%lu: Write set size: %lu\n", pthread_self(), t->write_set.size);
    for (uint64_t i = 0; i < t->write_set.size; i++) {
        // printf("%lu: %lld\n", pthread_self(),i);
        // struct segment *segment = t->write_set.pairs[i].segment;
        struct version_lock *lock = t->write_set.pairs[i].lock;

        if ( // atomic_load(&segment->alloc_lock) ||
            atomic_exchange(&lock->write_lock, true)) {
            // TODO: Abort transaction by reversing the reads
            // and releaasing locks
            for (uint64_t j = 0; j < i; j++) {
                atomic_store(&t->write_set.pairs[j].lock->write_lock, false);
            }

            for (uint64_t k = 0; k < t->read_set.size; k++) {
                memcpy(t->read_set.pairs[k].value,
                       t->read_set.pairs[k].previous_value,
                       t->read_set.pairs[k].size);
                free(t->read_set.pairs[k].previous_value);
            }

            return false;
        }
    }
    printf("%lu: Acquired locks\n", pthread_self());

    uint64_t write_version = atomic_fetch_add(&region->global_version, 1) + 1;
    printf("%lu: Read version %llu Write version %llu", pthread_self(),
           t->read_version, write_version);

    printf("%lu: Read set size: %lu\n", pthread_self(), t->read_set.size);
    // Validate reads
    if (t->read_version + 1 != write_version) {
        for (uint64_t i = 0; i < t->read_set.size; i++) {
            // printf("%lu: %lld\n", pthread_self(), i);
            void *source = t->read_set.pairs[i].key;
            // struct segment *segment = t->read_set.pairs[i].segment;
            struct version_lock *lock = t->read_set.pairs[i].lock;

            void *write_value = map_get(&t->write_set, source);
            printf("%lu: Lock version: %lu\n", pthread_self(),
                   atomic_load(&lock->version));
            if ( // atomic_load(&segment->alloc_lock) ||
                (write_value == NULL && atomic_load(&lock->write_lock)) ||
                atomic_load(&lock->version) > t->read_version) {
                // TODO: Abort transaction by reversing the reads and
                // releasing locks
                for (uint64_t j = 0; j < t->write_set.size; j++) {
                    atomic_store(&t->write_set.pairs[j].lock->write_lock,
                                 false);
                }

                for (uint64_t k = 0; k < t->read_set.size; k++) {
                    memcpy(t->read_set.pairs[k].value,
                           t->read_set.pairs[k].previous_value,
                           t->read_set.pairs[k].size);
                    free(t->read_set.pairs[k].previous_value);
                }

                return false;
            }
        }
    }

    printf("%lu: Validated reads\n", pthread_self());

    // Execute writes
    // void **previous_writes =
    //     (void **)malloc(t->write_set.size * sizeof(void *));
    for (uint64_t i = 0; i < t->write_set.size; i++) {
        //     struct segment *segment = t->write_set.pairs[i].segment;

        // if (atomic_load(&segment->alloc_lock)) {
        //     // TODO: Release all write_locks
        //     // TODO: Abort transaction by reversing the reads and writes
        //     for (uint64_t j = 0; j < t->write_set.size; j++) {
        //         memcpy(t->write_set.pairs[j].key, previous_writes[j],
        //                t->write_set.pairs[j].size);
        //         free(previous_writes[j]);
        //         atomic_store(&t->write_set.pairs[j].lock->write_lock, false);
        //     }

        //     for (uint64_t k = 0; k < t->read_set.size; k++) {
        //         memcpy(t->read_set.pairs[k].value, previous_reads[k],
        //                t->read_set.pairs[k].size);
        //         free(previous_reads[k]);
        //     }

        //     return false;
        // }

        // previous_writes[i] = malloc(t->write_set.pairs[i].size);
        // memcpy(previous_writes[i], t->write_set.pairs[i].key,
        //        t->write_set.pairs[i].size);
        printf("%lu: Writing from: %p to: %p, size: %ld before value: %lu\n",
               pthread_self(), t->write_set.pairs[i].value,
               t->write_set.pairs[i].key, t->write_set.pairs[i].size,
               *(uint64_t *)t->write_set.pairs[i].key);
        memcpy(t->write_set.pairs[i].key, t->write_set.pairs[i].value,
               t->write_set.pairs[i].size);
        printf("%lu: Wrote value: %lu \n", pthread_self(),
               *(uint64_t *)t->write_set.pairs[i].value);
        // TODO: Doesn't have to be atomic because we hold the locks
        atomic_store(&t->write_set.pairs[i].lock->version, write_version);
    }

    printf("%lu: Executed writes\n", pthread_self());

    // TODO: tm_end(shared_t, tx_t)
    // Implement execution of transaction
    for (uint64_t k = 0; k < t->read_set.size; k++) {
        free(t->read_set.pairs[k].previous_value);
    }

    for (uint64_t j = 0; j < t->write_set.size; j++) {
        // free(previous_writes[j]);
        atomic_store(&t->write_set.pairs[j].lock->write_lock, false);
    }

    map_destroy(&t->read_set);
    map_destroy(&t->write_set);
    free(t);

    printf("%lu: Transaction ended\n", pthread_self());
    return true;
}

/** [thread-safe] Read operation in the given transaction, source in the shared
 *region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the
 *alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
 **/
bool tm_read(shared_t shared, tx_t tx, void const *source_ptr, size_t size,
             void *target) {
    // We have to read here!
    // printf("Adding read to transaction\n");
    struct region *region = (struct region *)shared;
    struct transaction *t = (struct transaction *)tx;
    uintptr_t source = (uintptr_t)source_ptr;
    // printf("Target: %p\n", target);

    struct segment *current = region->segments;
    while (current != NULL) {
        uintptr_t segment_start = (uintptr_t)current + sizeof(struct segment);
        if (source >= segment_start && source < segment_start + current->size) {
            // printf("Found address\n");
            struct version_lock *lock =
                &current->locks[(uint64_t)(source - segment_start) /
                                region->align];

            struct map_value *write_value =
                map_get(&t->write_set, (void *)source_ptr);

            if ( // atomic_load(&segment->alloc_lock) ||
                 //  Here we actually can immediately check if the write_lock
                 //  is aquired even if the read value is in the write set
                 //   (i.e. write_value == NULL), because it will fail the
                 //   transaction afterwards because the lock is still taken
                (write_value == NULL && atomic_load(&lock->write_lock)) ||
                atomic_load(&lock->version) > t->read_version) {
                // TODO: Abort transaction by reversing the reads and
                for (uint64_t k = 0; k < t->read_set.size; k++) {
                    memcpy(t->read_set.pairs[k].value,
                           t->read_set.pairs[k].previous_value,
                           t->read_set.pairs[k].size);
                    free(t->read_set.pairs[k].previous_value);
                }

                return false;
            }

            void *copy_from =
                write_value == NULL ? (void *)source_ptr : write_value->value;
            void *previous_value = malloc(size);
            memcpy(previous_value, target, size);
            memcpy(target, copy_from, size);
            map_set(&t->read_set, (void *)copy_from, target, size, current,
                    lock, previous_value);
            printf("%lu: Read from %p to %p value: %lu\n", pthread_self(),
                   copy_from, target, *(uint64_t *)copy_from);
            break;
        }
        current = current->next;
    }
    // printf("Added read to transaction %lu\n", current == NULL);

    return current != NULL;
}

/** [thread-safe] Write operation in the given transaction, source in a private
 *region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the
 *alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
 **/
bool tm_write(shared_t unused(shared), tx_t tx, void const *source, size_t size,
              void *target_ptr) {
    // printf("Adding write to transaction\n");
    struct region *region = (struct region *)shared;
    struct transaction *t = (struct transaction *)tx;
    uintptr_t target = (uintptr_t)target_ptr;

    struct segment *current = region->segments;
    while (current != NULL) {
        uintptr_t segment_start = (uintptr_t)current + sizeof(struct segment);
        // printf("Source: %p Segment: %p Size: %ld\n", (void *)target,
        //        (void *)segment_start, current->size);
        if (target >= segment_start && target < segment_start + current->size) {
            // printf("Found address\n");
            struct version_lock *lock =
                &current->locks[(uint64_t)(target - segment_start) /
                                region->align];
            struct map_value *write_value = map_get(&t->write_set, target_ptr);

            if (write_value == NULL) {
                void *new_source = malloc(size);
                memcpy(new_source, source, size);
                map_set(&t->write_set, target_ptr, new_source, size, current,
                        lock, NULL);
                printf("%lu: Added write from %p to %p, value: %lu\n",
                       pthread_self(), source, target_ptr,
                       *(uint64_t *)new_source);
            } else {
                void *before = write_value->value;
                memcpy(write_value->value, source, size);
                printf("%lu: Changed write from %p (before %p) to %p, value: "
                       "%lu\n",
                       pthread_self(), write_value->value, before, target_ptr,
                       *(uint64_t *)write_value);
            }
            break;
        }

        current = current->next;
    }
    // printf("Added write to transaction %lu\n", current == NULL);
    return current != NULL;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive
 *multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first
 *byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not
 *(abort_alloc)
 **/
alloc_t tm_alloc(shared_t unused(shared), tx_t unused(tx), size_t unused(size),
                 void **unused(target)) {
    // TODO: tm_alloc(shared_t, tx_t, size_t, void**)
    return abort_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment
 *to deallocate
 * @return Whether the whole transaction can continue
 **/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void *unused(target)) {
    // TODO: tm_free(shared_t, tx_t, void*)
    return false;
}
