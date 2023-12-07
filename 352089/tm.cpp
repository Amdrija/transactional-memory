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
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <unordered_map>
#include <vector>
// Internal headers
#include <tm.hpp>

#include "macros.h"

struct VersionLock {
    uintptr_t segment_start;
    std::atomic<bool> write_lock;
    uint64_t version;
};

struct Segment {
    Segment *prev;
    Segment *next;
    size_t size;
};

inline Segment *get_segment_from_start_address(void *address) {
    return (Segment *)((uintptr_t)address - sizeof(Segment) -
                       sizeof(VersionLock));
}

inline uintptr_t get_segment_start(Segment *segment) {
    return (uintptr_t)segment + sizeof(Segment) + sizeof(VersionLock);
}

inline VersionLock *get_lock(uintptr_t address) {
    return (VersionLock *)((uintptr_t)address - sizeof(VersionLock));
}

// This here is the chicken end egg problem,
// however, I could potentially encode a value in bits 49-62
// to signal that this pointer is a pointer to segment_start,
// therefore, that location contains the write_lock
// This could be solved then just by traversing upwards to find
// a special pointer, then we can remove the flag and red the
// value of segment start, and then calculate the offset and get
// the proper location. This traversing upwards will at most be
// the size of the version lock.
inline uintptr_t convert_address(uintptr_t address, size_t align) {
    VersionLock *lock = get_lock(address);
    printf("%lu: Got lock: %p %p %lu %lu\n", pthread_self(), lock,
           lock->segment_start, lock->version, lock->write_lock.load());
    size_t offset =
        (address - lock->segment_start) / align * (sizeof(VersionLock) + align);
    printf("%lu: Offset: %lu\n", pthread_self(), offset);

    auto result = address + offset + sizeof(VersionLock);
    printf("%lu: Result: %lu\n", pthread_self(), result);

    return address + offset + sizeof(VersionLock);
}

struct Region {
    std::atomic<uint64_t> global_version;
    Segment *segments;
    Segment *last_segment;
    size_t align;
    std::mutex alloc_lock;

    static Region *create(size_t size, size_t align) {
        Region *region = new Region();

        region->align = align;
        region->global_version.store(0);

        // Not sure what would happen if I have the alignment, but also align
        // the version locks
        size_t version_lock_count = size / align;
        size_t segment_size =
            sizeof(Segment) + sizeof(VersionLock) * version_lock_count + size;
        if (unlikely(posix_memalign((void **)&region->segments, region->align,
                                    segment_size) != 0)) { // Allocation failed
            delete region;

            return NULL;
        }

        memset(region->segments, 0, segment_size);
        region->last_segment = region->segments;
        region->segments->prev = NULL;
        region->segments->next = NULL;
        region->segments->size = size;

        for (size_t i = 0; i < version_lock_count; i++) {
            VersionLock *lock =
                (VersionLock *)((uintptr_t)region->segments + sizeof(Segment) +
                                i * (sizeof(VersionLock) + align));
            lock->segment_start = get_segment_start(region->segments);
        }

        printf("%lu: Initialized region\n", pthread_self());

        return region;
    }

    ~Region() {
        // printf("%lu: Deleting region\n", pthread_self());

        while (segments != NULL) {
            Segment *next = segments->next;
            free(segments);
            segments = next;
        }
    }
};

struct Read {
    void const *source_shared;
    void *target_private;
    size_t size;
    VersionLock *lock;

    Read(void const *source_shared, void *target_private, size_t size,
         VersionLock *lock)
        : source_shared(source_shared), target_private(target_private),
          size(size), lock(lock) {
        // printf("%lu: Reading from %p to %p value: %lu\n", pthread_self(),
        //        source_shared, target_private, *(uint64_t *)source_shared);

        std::memcpy(target_private, source_shared, size);

        // printf("%lu: Read from %p to %p value: %lu\n", pthread_self(),
        //        source_shared, target_private, *(uint64_t *)target_private);
    }
};

struct Write {
    uint8_t *value;
    void *target_shared;
    size_t size;
    VersionLock *lock;

    Write(void const *source_private, void *target_shared, size_t size,
          VersionLock *lock)
        : value(new uint8_t[size]), target_shared(target_shared), size(size),
          lock(lock) {
        // Here we have to remember the value, because the source is only going
        // to be visible during the call to write
        // printf("%lu: Writting from %p to %p value: %lu\n", pthread_self(),
        //        source_private, target_shared, *(uint64_t *)source_private);

        std::memcpy(value, source_private, size);

        // printf("%lu: Written from %p to %p value: %lu (address: %p)\n",
        //        pthread_self(), source_private, target_shared,
        //        *(uint64_t *)value, value);
    }

    void overwrite(void const *source_private, size_t size) {
        // printf("%lu: Overwritting from %p to %p value: %lu\n",
        // pthread_self(),
        //        source_private, target_shared, *(uint64_t *)source_private);

        delete[] value;
        value = new uint8_t[size];

        std::memcpy(value, source_private, size);

        // printf("%lu: Overwritten from %p to %p value: %lu (address: %p)\n",
        //        pthread_self(), source_private, target_shared,
        //        *(uint64_t *)value, value);
    }

    void execute(uint64_t version) {
        // printf("%lu: Executing write from %p to %p value: %lu\n",
        //        pthread_self(), value, target_shared, *(uint64_t *)value);

        this->lock->version = version;
        std::memcpy(target_shared, value, size);

        // printf("%lu: Executed write from %p to %p value: %lu\n",
        // pthread_self(),
        //        value, target_shared, *(uint64_t *)value);
    }

    ~Write() {
        // printf("Deleting %p\n", this->target_shared);
        // If i include this delte I get double free?

        delete[] value;

        // printf("Deleted %p\n", this->target_shared);
    }
};

struct Transaction {
    std::vector<std::unique_ptr<Read>> read_set;
    std::unordered_map<uintptr_t, std::unique_ptr<Write>> write_set;
    uint64_t read_version;
    bool is_read_only;

    Transaction(uint64_t read_version, bool is_ro)
        : read_version(read_version), is_read_only(is_ro) {}

    static void
    abort(Transaction *t,
          std::unordered_map<uintptr_t, std::unique_ptr<Write>>::const_iterator
              limit) {
        t->release_locks(limit);
        delete t;
    }

    static void finish(Transaction *t) {
        t->release_locks(t->write_set.cend());

        delete t;
    }

    void release_locks(
        std::unordered_map<uintptr_t, std::unique_ptr<Write>>::const_iterator
            limit) {
        for (auto i = this->write_set.cbegin(); i != limit; i++) {
            i->second->lock->write_lock.store(false);
        }
    }
};

/** Create (i.e. allocate + init) a new shared memory region, with one first
 *non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in
 *bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared
 *memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
 **/
shared_t tm_create(size_t size, size_t align) noexcept {
    Region *region = Region::create(size, align);

    // printf("%lu: Created region\n", pthread_self());

    return region == NULL ? invalid_shared : (shared_t)region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
 **/
void tm_destroy(shared_t shared) noexcept {
    auto region = (Region *)shared;
    delete region;

    // printf("%lu: Deleted region\n", pthread_self());
}

/** [thread-safe] Return the start address of the first allocated segment in the
 *shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
 **/
void *tm_start(shared_t shared) noexcept {
    auto region = (Region *)shared;
    auto start_address = (void *)get_segment_start(region->segments);

    // printf("%lu: Started transaction: %p, %p\n", pthread_self(),
    //        region->segments, start_address);

    return start_address;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of
 *the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
 **/
size_t tm_size(shared_t shared) noexcept {
    auto region = (Region *)shared;

    return region->segments->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the
 *given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
 **/
size_t tm_align(shared_t unused(shared)) noexcept {
    auto region = (Region *)shared;

    return region->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
 **/
tx_t tm_begin(shared_t shared, bool is_ro) noexcept {
    auto region = (Region *)shared;
    Transaction *transaction =
        new Transaction(region->global_version.load(), is_ro);

    // printf("%lu: Began transaction\n", pthread_self());

    return (tx_t)transaction;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
 **/
bool tm_end(shared_t shared, tx_t tx) noexcept {
    // printf("%lu: Ending transaction\n", pthread_self());

    auto region = (Region *)shared;
    auto transaction = (Transaction *)tx;

    if (transaction->is_read_only) {
        Transaction::finish(transaction);

        return true;
    }

    // Acquire locks for each value in the write set
    // printf("%lu: Write Set: %lu\n", pthread_self(),
    //        transaction->write_set.size());

    for (auto i = transaction->write_set.cbegin();
         i != transaction->write_set.cend(); i++) {

        // printf("%lu: Acquiring lock: %p Lock: %d\n", pthread_self(),
        //        i->second->target_shared,
        //        i->second->lock->write_lock.load());

        VersionLock *lock = i->second->lock;
        if (lock->write_lock.exchange(true)) {
            // TODO: Abort transaction
            Transaction::abort(transaction, i);

            return false;
        }

        // printf("%lu: Acquiring lock: %p Lock: %d\n", pthread_self(),
        //        i->second->target_shared,
        //        i->second->lock->write_lock.load());
    }

    // printf("%lu: Acquired locks\n", pthread_self());

    uint64_t write_version = region->global_version.fetch_add(1) + 1;

    // printf("%lu: Incremented global version %lu\n", pthread_self(),
    //        write_version);

    if (transaction->read_version + 1 != write_version) {
        for (auto &read : transaction->read_set) {
            auto write_value =
                transaction->write_set.find((uintptr_t)read->source_shared);
            if ((write_value == transaction->write_set.cend() &&
                 read->lock->write_lock.load()) ||
                transaction->read_version < read->lock->version) {
                // TODO: Abort transaction
                Transaction::abort(transaction, transaction->write_set.cend());

                return false;
            }
        }
    }

    // printf("%lu: Validated reads\n", pthread_self());

    for (auto &[_, write] : transaction->write_set) {
        write->execute(write_version);
    }

    // printf("%lu: Executed writes\n", pthread_self());

    Transaction::finish(transaction);

    // printf("%lu: Ended transaction\n", pthread_self());

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
bool tm_read(shared_t shared, tx_t tx, void const *source, size_t size,
             void *target) noexcept {
    // printf("%lu: Adding read\n", pthread_self());

    auto region = (Region *)shared;
    auto transaction = (Transaction *)tx;
    uintptr_t source_int = (uintptr_t)source;

    Segment *current = region->segments;
    while (current != NULL) {
        uintptr_t segment_start = get_segment_start(current);
        if (source_int >= segment_start &&
            source_int < segment_start + current->size) {
            printf("%lu: Converting address: %p\n", pthread_self(), source_int);
            source_int = convert_address(source_int, region->align);
            printf("%lu: Converted address: %p\n", pthread_self(), source_int);

            auto write = transaction->write_set.find(source_int);
            if (write == transaction->write_set.cend()) {
                VersionLock *lock = get_lock(source_int);

                if (lock->write_lock.load() ||
                    transaction->read_version < lock->version) {
                    // TODO: Abort transaction
                    Transaction::abort(transaction,
                                       transaction->write_set.cbegin());

                    return false;
                }
                uint64_t last_version = lock->version;

                transaction->read_set.push_back(std::make_unique<Read>(
                    (void *)source_int, target, size, lock));

                if (lock->write_lock.load() ||
                    transaction->read_version < lock->version ||
                    last_version != lock->version) {
                    // TODO: Abort transaction
                    Transaction::abort(transaction,
                                       transaction->write_set.cbegin());

                    return false;
                }
            } else {
                // printf("%lu: Found value %p %p\n", pthread_self(),
                //        write->second->target_shared, write->second->value);

                transaction->read_set.push_back(std::make_unique<Read>(
                    write->second->value, target, size, write->second->lock));
            }

            break;
        }

        current = current->next;
    }

    // printf("%lu: Added read\n", pthread_self());

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
bool tm_write(shared_t shared, tx_t tx, void const *source, size_t size,
              void *target) noexcept {
    // printf("%lu: Adding write\n", pthread_self());

    auto region = (Region *)shared;
    auto transaction = (Transaction *)tx;
    uintptr_t target_int = (uintptr_t)target;

    Segment *current = region->segments;
    while (current != NULL) {
        uintptr_t segment_start = get_segment_start(current);
        if (target_int >= segment_start &&
            target_int < segment_start + current->size) {
            printf("%lu: Convert address: %p\n", pthread_self(), target_int);
            target_int = convert_address(target_int, region->align);
            printf("%lu: Convert address: %p\n\n", pthread_self(), target_int);
            VersionLock *lock = get_lock(target_int);

            auto write = transaction->write_set.find(target_int);
            if (write == transaction->write_set.cend()) {
                transaction->write_set.emplace(
                    target_int, std::make_unique<Write>(
                                    source, (void *)target_int, size, lock));
            } else {
                write->second->overwrite(source, size);
            }

            break;
        }
        current = current->next;
    }

    // printf("%lu: Added write: %d\n", pthread_self(), current != NULL);

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
Alloc tm_alloc(shared_t shared, tx_t tx, size_t size, void **target) noexcept {
    // auto region = (Region *)shared;

    // if (region->alloc_lock.exchange(true)) {
    //     return Alloc::abort;
    // }

    // Segment *new_segment;
    // if (unlikely(posix_memalign((void **)&new_segment, region->align,
    //                             sizeof(Segment) + size) !=
    //              0)) { // Allocation failed
    //     return Alloc::nomem;
    // }

    // new_segment->prev = region->last_segment;
    // new_segment->next = NULL;
    // new_segment->size = size;

    // new_segment->locks =
    //     (VersionLock *)malloc(sizeof(VersionLock) * size / region->align);
    // if (unlikely(!new_segment->locks)) {
    //     free(new_segment);

    //     return Alloc::nomem;
    // }

    // region->last_segment = new_segment;

    // region->alloc_lock.store(false);

    // memset(new_segment, 0, size);

    // *target = (void *)get_segment_start(new_segment);

    return Alloc::success;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment
 *to deallocate
 * @return Whether the whole transaction can continue
 **/
bool tm_free(shared_t shared, tx_t unused(tx), void *target) noexcept {
    // auto region = (Region *)shared;

    // if (region->alloc_lock.exchange(true)) {
    //     return false;
    // }

    // Segment *segment = get_segment_from_start_address(target);
    // for (size_t i = 0; i < segment->size / region->align; i++) {
    //     if (segment->locks[i].write_lock.exchange(true)) {
    //         for (size_t j = 0; j < i; j++) {
    //             segment->locks[j].write_lock.store(false);
    //         }

    //         region->alloc_lock.store(false);

    //         return false;
    //     }
    // }

    // if (segment->next != NULL) {
    //     segment->next->prev = segment->prev;
    // }

    // // here we don't have to check because the first segment will never be
    // // deallocated
    // segment->prev->next = segment->next;

    // free(segment->locks);
    // free(segment);

    return true;
}
