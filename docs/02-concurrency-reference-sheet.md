# Reference Sheet 02: Concurrency in Java

The runnable version is `tour/ConcurrencyTour.java` (14 lessons). Click Run above `main()`.

## The problem

Two threads doing `count++` at once can both read 5 and both write 6: one update is lost. This is a **race condition**.

## Four ways to be safe

| Tool | Use it when | Cost |
|---|---|---|
| Give each thread its own data, merge at the end | You can split the work (best option, used here) | None while working |
| `AtomicLong` / `LongAdder` | A shared counter | Small; `LongAdder` is faster with many threads |
| `ConcurrentHashMap` | A shared map | Small |
| `ReentrantLock` / `synchronized` | A group of changes must happen together | Threads wait for each other |

```java
lock.lock();
try { shared++; } finally { lock.unlock(); }   // ALWAYS unlock in finally
```

## Running work on threads

```java
ExecutorService pool = Executors.newFixedThreadPool(4);       // platform threads
Future<Integer> f = pool.submit(() -> compute());             // returns a result later
int result = f.get();                                         // waits
pool.shutdown();                                              // or the program never exits

try (var ex = Executors.newVirtualThreadPerTaskExecutor()) {  // Java 21: one cheap thread per task
    ex.submit(() -> doWork());
}                                                             // close() waits for the tasks
```

`CompletableFuture.supplyAsync(...).thenApply(...).thenCombine(...)` chains steps without blocking.

## Which one when?

| Work type | Best tool | Why |
|---|---|---|
| CPU-bound (parsing, maths) | Thread pool sized to the cores | More threads than cores cannot make a core faster |
| Waiting-bound (network, slow disk, database) | Virtual threads | A waiting virtual thread costs almost nothing |

## Gotchas

- Lambdas can only use variables that are **effectively final**.
- A semaphore limits how many tasks run at the same moment (`acquire()` / `release()`): this is how memory stays bounded.
- Unlimited threads is not free: each running chunk here holds a 256 KB buffer.
- Always measure. Parallel code can be slower than sequential code on small inputs or a single core.
