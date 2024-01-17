# Transactional Memory

Transactional Memory is a concurrency primitive designed to make memory sharing between multiple threads as easy as having 1 lock on the entire shared memory region, while also scaling linearly with the number of threads.

It is very easy to introduce errors and deadlocks when using fine-grained locks and global locks scale poorly with the number of concurrent processes, as every other process is waiting to acquire the lock to enter the critical section.

## How to use

Consider a use case where a bank has 10 accounts and it wants to handle transactions concurrently in order to scale the number of transactions per second.

First, the user of this library would have to create a shared memory region, holding 10 accounts (the balance of an account is an `int`):

```c
shared_t region = tm_create(sizeof(int) * 10, sizeof(int)); 

void *accounts = tm_start(region); //gets the start address of the memory segment which hold 10 account balances
```

The `shared_t tm_create(size_t size, size_t alignment)` function takes in the size of the memory region and the alignment and returns a pointer to the requested memory region.

The `void *tm_start(shared_t region)` function returns the starting address of the shared memory.

Now, in order to transfer money from accounts[1] to accounts[2], you can call `bool tm_read(shared_t region, tx_t transaction, void const* read_from, size_t size, void* write_read_value_to)` to read and `bool     tm_write(shared_t region, tx_t transaction, void const* write_to, size_t size, void* address_of_value)`. The `tm_read` function returns false if the transaction should be aborted. You can ignore this value and still continue the transaction, but when calling `tm_end(shared_t region, tx_t transaction)`, it will return false, aborting the transaction and forcing you to retry it. The `tm_write` call will always return true, as the writes are performed only at the end of the transaction. Here is the example code:

```c
txt_t transaction;
int account_from = 0;
int account_to = 0;

do {
    transaction = tm_begin(context, false);

    tm_read(context, transaction, &accounts[1], &account_from);
    tm_read(context, transaction, &account[2], &account_to);

    account_from -= 10;
    account_to += 10;

    tm_write(context, transaction, &account_from, sizeof(int), &accounts[1]);
    tm_write(context, transaction, &account_to, sizeof(int), &accounts[2]);

} while (!tm_end(context, transaction));
```

## Transactional Locking II (TL2)

Here is a brief explanation of the [TL2](https://dcl.epfl.ch/site/_media/education/4.pdf) algorithm. This algorithm wasn't originally proposed by the Concurrent Algorithms course. It was mentioned that we could implement it, but we are completely on our own and we have to understand it from the paper. However, it was also mentioned that it is one of the fastest algorithms available. The current, highly unoptimised implementation of this algorithm is 2.5 times faster than the reference implementation which uses one global lock. However, I have managed to implement a much faster version in C (around 4 times faster than the reference). With some tricks, it is possible to achieve a 10 time speedup as well.

First, we have to define some terms:

* Global version clock: contains the most recent version of the region.
* Read set: a set of sources in shared memory to read from and their respective locations outside to copy the value to.  
* Write set: a set of targets in shared memory to write to and their respective locations outside to copy the value from.  
* Write Lock: contains the version number of the word and a lock.
* Segment: Part of shared memory which contains words (aligned) and a pointer to Write Locks corresponding to each word.  
* Segment List: List of segments  

When writing:

1. Get global version clock and store it in transactions read version number.
2. Execute reads, check if their source is in the write set, if it is, copy the new value in write set. Otherwise, check if the Write Lock of the read's source is free and it's version number is <= transaction's read version number, if it isn't, abort.
3. Lock the write set, if not able to acquire all lock, abort.
4. Increment and fetch global versioned clock and save it in write version number.
5. Validate the read set again by checking if the corresponding lock is free (in case it's not in the write set) and if lock's version number <= read version. Otherwise abort. If read version + 1 = write version, then there's no need to validate the read set as it is not possible that some other thread wrote in the meantime.
6. Write the write set and store the new write version.

Read-only transaction:

1. Get global version clock and store it in transactions read version number
2. Execute reads, check if the Write Lock of the read's source is free and it's version number is <= transaction's read version number, if it isn't, abort, reversing the already copied reads.

## CS-453 - Course project

The [project description](https://dcl.epfl.ch/site/_media/education/ca-project.pdf) is available on [Moodle](https://moodle.epfl.ch/course/view.php?id=14334) and the [website of the course](https://dcl.epfl.ch/site/education/ca_2021).

The description includes:

* an introduction to (software) transactional memory
* an introduction to concurrent programming in C11/C++11, with pointers to more resources
* the _specifications_ of the transactional memory you have to implement, i.e. both:
  * sufficient properties for a transactional memory to be deemed _correct_
  * a thorough description of the transactional memory interface
* practical informations, including:
  * how to test your implementation on your local machine and on the evaluation server
  * how your submission will be graded
  * rules for (optionally) using 3rd-party libraries and collaboration (although the project is _individual_)

This repository provides:

* examples of how to use synchronization primitives (in `sync-examples/`)
* a reference implementation (in `reference/`)
* a "skeleton" implementation (in `template/`)
  * this template is written in C11
  * feel free to overwrite it completely if you prefer to use C++ (in this case include `<tm.hpp>` instead of `<tm.h>`)
* the program that will test your implementation (in `grading/`)
  * the same program will be used on the evaluation server (although possibly with a different seed)
  * you can use it to test/debug your implementation on your local machine (see the [description](https://dcl.epfl.ch/site/_media/education/ca-project.pdf))
* a tool to submit your implementation (in `submit.py`)
  * you should have received by mail a secret _unique user identifier_ (UUID)
  * see the [description](https://dcl.epfl.ch/site/_media/education/ca-project.pdf) for more information
