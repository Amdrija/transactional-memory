/**
 * @file   workload.hpp
 * @author Sébastien Rouault <sebastien.rouault@epfl.ch>
 *
 * @section LICENSE
 *
 * Copyright © 2018-2019 Sébastien Rouault.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * any later version. Please see https://gnu.org/licenses/gpl.html
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * @section DESCRIPTION
 *
 * Workload base class and derived workload(s) implementations.
 **/

#pragma once

// External headers
#include <cstdint>
#include <random>

// Internal headers
#include "common.hpp"

// -------------------------------------------------------------------------- //

/** Worker unique ID type.
 **/
using Uid = uint_fast32_t;

/** Seed type.
 **/
using Seed = uint_fast32_t;

/** Workload base class.
 **/
class Workload {
protected:
    TransactionalLibrary const &tl; // Associated transactional library
    TransactionalMemory tm;         // Built transactional memory to use
public:
    /** Deleted copy constructor/assignment.
     **/
    Workload(Workload const &) = delete;
    Workload &operator=(Workload const &) = delete;
    /** Transactional memory constructor.
     * @param library Transactional library to use
     * @param align   Shared memory region required alignment
     * @param size    Size of the shared memory region to allocate
     **/
    Workload(TransactionalLibrary const &library, size_t align, size_t size)
        : tl{library}, tm{tl, align, size} {}
    /** Virtual destructor.
     **/
    virtual ~Workload(){};

public:
    /** Shared memory (re)initialization.
     * @return Constant null-terminated error message, 'nullptr' for none
     **/
    virtual char const *init() const = 0;
    /** [thread-safe] Worker's full run.
     * @param Unique ID (between 0 to n-1)
     * @param Seed to use
     * @return Constant null-terminated error message, 'nullptr' for none
     **/
    virtual char const *run(Uid, Seed) const = 0;
    /** [thread-safe] Worker's false negative-free check.
     * @param Unique ID (between 0 to n-1)
     * @param Seed to use
     * @return Constant null-terminated error message, 'nullptr' for none
     **/
    virtual char const *check(Uid, Seed) const = 0;
};

// -------------------------------------------------------------------------- //

/** Bank workload class.
 **/
class WorkloadBank final : public Workload {
public:
    /** Account balance class alias.
     **/
    using Balance = intptr_t;
    static_assert(sizeof(Balance) >= sizeof(void *),
                  "Balance class is too small");

private:
    /** Shared segment of accounts class.
     **/
    class AccountSegment final {
    private:
        /** Dummy structure for size and alignment retrieval.
         **/
        struct Dummy {
            size_t dummy0;
            void *dummy1;
            Balance dummy2;
            Balance dummy3[];
        };

    public:
        /** Get the segment size for a given number of accounts.
         * @param nbaccounts Number of accounts per segment
         * @return Segment size (in bytes)
         **/
        constexpr static auto size(size_t nbaccounts) noexcept {
            return sizeof(Dummy) + nbaccounts * sizeof(Balance);
        }
        /** Get the segment alignment for a given number of accounts.
         * @return Segment size (in bytes)
         **/
        constexpr static auto align() noexcept { return alignof(Dummy); }

    public:
        Shared<size_t> count; // Number of allocated accounts in this segment
        Shared<AccountSegment *> next; // Next allocated segment
        Shared<Balance>
            parity; // Segment balance correction for when deleting an account
        Shared<Balance[]> accounts; // Amount of money on the accounts
                                    // (undefined if not allocated)
    public:
        /** Deleted copy constructor/assignment.
         **/
        AccountSegment(AccountSegment const &) = delete;
        AccountSegment &operator=(AccountSegment const &) = delete;
        /** Binding constructor.
         * @param tx      Associated pending transaction
         * @param address Block base address
         **/
        AccountSegment(Transaction &tx, void *address)
            : count{tx, address}, next{tx, count.after()},
              parity{tx, next.after()}, accounts{tx, parity.after()} {}
    };

private:
    size_t nbworkers;  // Number of concurrent workers
    size_t nbtxperwrk; // Number of transactions per worker
    size_t nbaccounts; // Initial number of accounts and number of accounts per
                       // segment
    size_t expnbaccounts; // Expected total number of accounts
    Balance init_balance; // Initial account balance
    float prob_long;      // Probability of running a long, read-only control
                          // transaction
    float prob_alloc;     // Probability of running an allocation/deallocation
                          // transaction, knowing a long transaction won't run
    Barrier barrier;      // Barrier for thread synchronization during 'check'
public:
    /** Bank workload constructor.
     * @param library       Transactional library to use
     * @param nbworkers     Total number of concurrent threads (for both 'run'
     *and 'check')
     * @param nbtxperwrk    Number of transactions per worker
     * @param nbaccounts    Initial number of accounts and number of accounts
     *per segment
     * @param expnbaccounts Initial number of accounts and number of accounts
     *per segment
     * @param init_balance  Initial account balance
     * @param prob_long     Probability of running a long, read-only control
     *transaction
     * @param prob_alloc    Probability of running an allocation/deallocation
     *transaction, knowing a long transaction won't run
     **/
    WorkloadBank(TransactionalLibrary const &library, size_t nbworkers,
                 size_t nbtxperwrk, size_t nbaccounts, size_t expnbaccounts,
                 Balance init_balance, float prob_long, float prob_alloc)
        : Workload{library, AccountSegment::align(),
                   AccountSegment::size(nbaccounts)},
          nbworkers{nbworkers}, nbtxperwrk{nbtxperwrk}, nbaccounts{nbaccounts},
          expnbaccounts{expnbaccounts}, init_balance{init_balance},
          prob_long{prob_long}, prob_alloc{prob_alloc},
          barrier{static_cast<Barrier::Counter>(nbworkers)} {}

private:
    /** Long read-only transaction, summing the balance of each account.
     * @param count Loosely-updated number of accounts
     * @return Whether no inconsistency has been found
     **/
    bool long_tx(size_t &nbaccounts) const {
        return transactional(
            tm, Transaction::Mode::read_only, [&](Transaction &tx) {
                auto count = 0ul; // Total number of accounts seen.
                auto sum = Balance{
                    0}; // Total balance on all seen accounts + parity ammount.
                auto start =
                    tm.get_start(); // The list of accounts starts at the first
                                    // word of the shared memory region.
                while (start) {
                    AccountSegment segment{
                        tx, start}; // We interpret the memory as a
                                    // segment/array of accounts.
                    decltype(count) segment_count = segment.count;
                    count += segment_count; // And accumulate the total number
                                            // of accounts.
                    sum += segment.parity; // We also sum the money that results
                                           // from the destruction of accounts.
                    for (decltype(count) i = 0; i < segment_count; ++i) {
                        Balance local = segment.accounts[i];
                        if (unlikely(
                                local <
                                0)) // If one account has a negative balance,
                                    // there's a consistency issue.
                            return false;
                        sum += local;
                    }
                    start = segment.next; // Accounts are stored in linked
                                          // segments, we move to the next one.
                }
                nbaccounts = count;
                return sum ==
                       static_cast<Balance>(
                           init_balance *
                           count); // Consistency check: no money should ever be
                                   // destroyed or created out of thin air.
            });
    }
    /** Account (de)allocation transaction, adding accounts with initial balance
     *or removing them.
     * @param trigger Trigger level that will decide whether to allocate or
     *deallocate
     **/
    void alloc_tx(size_t trigger) const {
        return transactional(
            tm, Transaction::Mode::read_write, [&](Transaction &tx) {
                auto count = 0ul; // Total number of accounts seen.
                void *prev = nullptr;
                auto start = tm.get_start();
                while (true) {
                    AccountSegment segment{tx, start};
                    decltype(count) segment_count = segment.count;
                    count += segment_count;
                    decltype(start) segment_next = segment.next;
                    if (!segment_next) { // Currently at the last segment
                        if (count > trigger &&
                            likely(count >
                                   2)) { // If we have seen "too many" accounts,
                                         // we will destroy one.
                            --segment_count; // Let's remove the last account
                                             // from the last segment.
                            auto new_parity =
                                segment.parity.read() +
                                segment.accounts[segment_count] -
                                init_balance; // We remove 1x the initial
                                              // balance but don't break parity.
                            if (segment_count >
                                0) { // Just remove one account from the (last)
                                     // segment without deallocating memory.
                                segment.count = segment_count;
                                segment.parity = new_parity;
                            } else { // If there's no one in the last segment
                                     // anymore, we deallocate it.
                                if (unlikely(assert_mode && prev == nullptr))
                                    throw Exception::
                                        TransactionNotLastSegment{};
                                AccountSegment prev_segment{tx, prev};
                                prev_segment.next.free();
                                prev_segment.parity =
                                    prev_segment.parity.read() + new_parity;
                            }
                        } else { // If we don't destroy any account, then let's
                                 // create a new one.
                            if (segment_count <
                                nbaccounts) { // If there's room in the last
                                              // segment, then let's create the
                                              // account in it without
                                              // allocating memory.
                                segment.accounts[segment_count] = init_balance;
                                segment.count = segment_count + 1;
                            } else { // Otherwise, we really need to allocate
                                     // memory for the new account.
                                AccountSegment next_segment{
                                    tx, segment.next.alloc(
                                            AccountSegment::size(nbaccounts))};
                                next_segment.count = 1;
                                next_segment.accounts[0] = init_balance;
                            }
                        }
                        return;
                    }
                    prev = start;
                    start = segment_next;
                }
            });
    }
    /** Short read-write transaction, transferring one unit from an account to
     *an account (potentially the same).
     * @param send_id Index of the sender account
     * @param recv_id Index of the receiver account (potentially same as source)
     * @return Whether the parameters were satisfying and the transaction
     *committed on useful work
     **/
    bool short_tx(size_t send_id, size_t recv_id) const {
        return transactional(
            tm, Transaction::Mode::read_write, [&](Transaction &tx) {
                void *send_ptr = nullptr;
                void *recv_ptr = nullptr;

                // Get the account pointers in shared memory
                auto start = tm.get_start();
                while (true) {
                    AccountSegment segment{tx, start};
                    size_t segment_count = segment.count;
                    if (!send_ptr) {
                        if (send_id < segment_count) {
                            send_ptr = segment.accounts[send_id].get();
                            if (recv_ptr)
                                break;
                        } else {
                            send_id -= segment_count;
                        }
                    }
                    if (!recv_ptr) {
                        if (recv_id < segment_count) {
                            recv_ptr = segment.accounts[recv_id].get();
                            if (send_ptr)
                                break;
                        } else {
                            recv_id -= segment_count;
                        }
                    }
                    start = segment.next;
                    if (!start)       // Current segment is the last segment
                        return false; // At least one account does not exist =>
                                      // do nothing
                }

                // Transfer the money if enough fund
                Shared<Balance> sender{
                    tx, send_ptr}; // Shared is a template that overloads copy
                                   // to use tm_read/tm_write.
                Shared<Balance> recver{tx, recv_ptr};
                auto send_val = sender.read();
                if (send_val > 0) {
                    sender = send_val - 1;
                    recver = recver.read() + 1;
                }
                return true;
            });
    }

public:
    /**
     * Initialize the first segment of accounts and check the initial ballance
     *(2 transactions).
     **/
    virtual char const *init() const {
        transactional(tm, Transaction::Mode::read_write, [&](Transaction &tx) {
            AccountSegment segment{tx, tm.get_start()};
            segment.count = nbaccounts;
            for (size_t i = 0; i < nbaccounts; ++i)
                segment.accounts[i] = init_balance;
        });
        auto correct = transactional(
            tm, Transaction::Mode::read_only, [&](Transaction &tx) {
                AccountSegment segment{tx, tm.get_start()};
                return segment.accounts[0] == init_balance;
            });
        if (unlikely(!correct))
            return "Violated consistency (check that committed writes in "
                   "shared memory get visible to the following transactions' "
                   "reads)";
        return nullptr;
    }

    /**
     * Run nbtxperwrk random transactions until completion.
     * @param seed Randomness source
     **/
    virtual char const *run(Uid uid [[gnu::unused]], Seed seed) const {
        ::std::minstd_rand engine{seed};
        ::std::bernoulli_distribution long_dist{prob_long};
        ::std::bernoulli_distribution alloc_dist{prob_alloc};
        ::std::gamma_distribution<float> alloc_trigger(expnbaccounts, 1);
        size_t count = nbaccounts;
        for (size_t cntr = 0; cntr < nbtxperwrk; ++cntr) {
            if (long_dist(engine)) { // We roll a dice and, if "lucky", run a
                                     // long transaction.
                if (unlikely(!long_tx(count))) // If it fails, then we return an
                                               // error message.
                    return "Violated isolation or atomicity";
            } else if (alloc_dist(
                           engine)) { // Let's roll a dice again to trigger an
                                      // allocation transaction.
                alloc_tx(alloc_trigger(engine));
            } else { // No luck with previous rolls, let's just run a short
                     // transaction.
                ::std::uniform_int_distribution<size_t> account{0, count - 1};
                while (unlikely(!short_tx(account(engine), account(engine))))
                    ;
            }
        }
        { // Last long transaction
            size_t dummy;
            if (!long_tx(dummy))
                return "Violated isolation or atomicity";
        }
        return nullptr;
    }
    /**
     * Test in which we check that multiple concurrent transactions can decrease
     *a counter in a sequential manner.
     * @param uid Id of the thread to run the check
     **/
    virtual char const *check(Uid uid, Seed seed [[gnu::unused]]) const {
        constexpr size_t nbtxperwrk = 100;

        barrier.sync();
        if (uid == 0) { // Only the first thread initializes the shared memory.
            // We first write the initial value,
            auto init_counter = nbtxperwrk * nbworkers;
            transactional(tm, Transaction::Mode::read_write,
                          [&](Transaction &tx) {
                              Shared<size_t> counter{tx, tm.get_start()};
                              counter = init_counter;
                          });

            // And check in another transaction that it was written correctly.
            auto correct = transactional(
                tm, Transaction::Mode::read_only, [&](Transaction &tx) {
                    Shared<size_t> counter{tx, tm.get_start()};
                    return counter == init_counter;
                });
            if (unlikely(!correct)) {
                barrier.sync();
                barrier.sync();
                return "Violated consistency during initialization";
            }
        }

        // In each thread,
        barrier.sync();
        for (size_t i = 0; i < nbtxperwrk; ++i) {

            // We first fetch the last value of the counter,
            auto last = transactional(
                tm, Transaction::Mode::read_only, [&](Transaction &tx) {
                    Shared<size_t> counter{tx, tm.get_start()};
                    return counter.read();
                });

            // And then we decrease the value of the counter after checking that
            // it didn't increase since the last read.
            auto correct = transactional(
                tm, Transaction::Mode::read_write, [&](Transaction &tx) {
                    Shared<size_t> counter{tx, tm.get_start()};
                    auto value = counter.read();
                    if (unlikely(value > last))
                        return false;
                    counter = value - 1;
                    return true;
                });
            if (unlikely(!correct)) {
                barrier.sync();
                return "Violated consistency, isolation or atomicity";
            }
        }

        // Finally, a last transaction runs in the first thread to check that
        // the counter reached 0 (i.e., each transaction decreased it by 1.).
        barrier.sync();
        if (uid == 0) {
            auto correct = transactional(
                tm, Transaction::Mode::read_only, [&](Transaction &tx) {
                    Shared<size_t> counter{tx, tm.get_start()};
                    std::cout << "Counter: " + std::to_string(counter.read())
                              << std::endl;
                    return counter == 0;
                });
            if (unlikely(!correct))
                return "Violated consistency";
        }
        return nullptr;
    }
};
