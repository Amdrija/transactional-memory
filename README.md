# CS-453 - Course project

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

## TL2

Global version clock -> contains the most recent version
Read set -> a set of sources in shared memory to read from and their respective locations outside to copy the value to.
Write set -> a set of targets in shared memory to write to and their respective locations outside to copy the value from.
Write Lock -> contains the version number of the word and a lock
Alloc Lock -> Each segments contains a value depicting whether there's a concurrent deallocation happening on that segment
Segment -> Part of shared memory which contains words (aligned) and a pointer to Write Locks corresponding to each word.
Segment List -> List of segments

When writing:

1. Get global version clock and store it in transactions read version number
2. Execute reads, check if their source is in the write set, if it is, copy the new value in write set. Otherwise, check if the Write Lock of the read's source is free and it's version number is <= transaction's read version number, if it isn't, abort, reversing the already copied reads.
3. Lock the write set, if not able to acquire all lock, abort, reversing the already copied reads.
4. Increment and fetch global versioned clock and save it in write version number
5. Validate the read set again by check if the corresponding lock is free (in case it's not in the write set) and if lock's version number <= read version. Otherwise abort and reverse the already copied reads. If read version + 1 = write version, then there's no need to validate the read set
6. Write the write set and store the new write version.

Read-only transaction:

1. Get global version clock and store it in transactions read version number
2. Execute reads, check if the Write Lock of the read's source is free and it's version number is <= transaction's read version number, if it isn't, abort, reversing the already copied reads.
