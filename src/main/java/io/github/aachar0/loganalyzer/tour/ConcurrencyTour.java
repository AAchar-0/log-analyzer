package io.github.aachar0.loganalyzer.tour;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * A runnable refresher for Java, with the focus on concurrency. Open this file in VS Code and click
 * "Run" above main(). Each numbered lesson prints what it does, so read the code and the output together.
 *
 * Lessons: 1 variables and control flow, 2 classes/records/enums/interfaces, 3 sealed types and pattern
 * matching, 4 collections and streams, 5 text blocks and strings, 6 exceptions, 7 threads,
 * 8 ExecutorService and Future, 9 CompletableFuture, 10 virtual threads, 11 shared counters (race vs safe),
 * 12 ConcurrentHashMap, 13 locks and semaphores, 14 CountDownLatch.
 */
public final class ConcurrencyTour {

    private ConcurrencyTour() {
    }

    // ---------------------------------------------------------------- lesson 2 helpers
    /** An enum is a fixed set of named values. It can hold data and methods. */
    enum Level {
        LOW(1), MEDIUM(5), HIGH(10);

        private final int weight;

        Level(int weight) {
            this.weight = weight;
        }

        int weight() {
            return weight;
        }
    }

    /** An interface says WHAT something can do. "default" methods give a ready-made body. */
    interface Greeter {
        String name();

        default String greet() {
            return "Hello, " + name() + "!";
        }
    }

    /** A record: immutable data with generated constructor, getters, equals, hashCode, toString. */
    record Person(String name, int age) implements Greeter {
        Person {                                       // compact constructor: validation runs on creation
            if (age < 0) {
                throw new IllegalArgumentException("age must not be negative");
            }
        }
    }

    /** A normal class: private fields, a constructor, methods. A static counter belongs to the class, not to objects. */
    static class Counter {
        private static int created = 0;
        private int value;

        Counter() {
            created++;
        }

        void increment() {
            value++;
        }

        int value() {
            return value;
        }

        static int created() {
            return created;
        }
    }

    // ---------------------------------------------------------------- lesson 3 helpers
    /** sealed: exactly these three shapes exist. The compiler can check a switch covers all of them. */
    sealed interface Shape permits Circle, Square, Rectangle {
    }

    record Circle(double radius) implements Shape {
    }

    record Square(double side) implements Shape {
    }

    record Rectangle(double width, double height) implements Shape {
    }

    static double area(Shape shape) {
        return switch (shape) {                        // pattern matching: test the type AND name the value
            case Circle c -> Math.PI * c.radius() * c.radius();
            case Square s -> s.side() * s.side();
            case Rectangle r -> r.width() * r.height();
        };
    }

    /** A generic method: works for any type T. */
    static <T extends Comparable<T>> T biggest(List<T> items) {
        T best = items.get(0);
        for (T item : items) {
            if (item.compareTo(best) > 0) {
                best = item;
            }
        }
        return best;
    }

    /** A custom (checked) exception: callers must handle or declare it. */
    static class BadInputException extends Exception {
        private static final long serialVersionUID = 1L;

        BadInputException(String message) {
            super(message);
        }
    }

    static int parsePositive(String text) throws BadInputException {
        try {
            int n = Integer.parseInt(text);
            if (n <= 0) {
                throw new BadInputException("not positive: " + n);
            }
            return n;
        } catch (NumberFormatException e) {                // unchecked exception from the library
            throw new BadInputException("not a number: " + text);
        }
    }

    static int sum(int... numbers) {                       // varargs: any number of ints
        int total = 0;
        for (int n : numbers) {
            total += n;
        }
        return total;
    }

    /** AutoCloseable + try-with-resources: close() is called automatically, even after an error. */
    static class Resource implements AutoCloseable {
        private final String name;

        Resource(String name) {
            this.name = name;
            System.out.println("  open " + name);
        }

        @Override
        public void close() {
            System.out.println("  close " + name);
        }
    }

    public static void main(String[] args) throws Exception {
        lesson1();
        lesson2();
        lesson3();
        lesson4();
        lesson5();
        lesson6();
        lesson7();
        lesson8();
        lesson9();
        lesson10();
        lesson11();
        lesson12();
        lesson13();
        lesson14();
    }

    static void title(String text) {
        System.out.println("\n=== " + text + " ===");
    }

    static void lesson1() {
        title("1. Variables and control flow");
        int count = 7;                                     // whole number
        long big = 3_000_000_000L;                         // needs L; underscores help reading
        double ratio = 7 / 2.0;                            // 3.5 (7 / 2 would be 3: integer division)
        boolean ok = count > 5 && ratio < 4;
        char letter = 'A';
        var inferred = "var lets the compiler pick the type";   // still strongly typed
        System.out.println(count + " " + big + " " + ratio + " " + ok + " " + letter + " " + inferred);

        for (int i = 0; i < 3; i++) {
            System.out.print("for" + i + " ");
        }
        int w = 0;
        while (w < 2) {
            w++;
        }
        do {
            w++;
        } while (w < 4);
        System.out.println("while/do-while ended at " + w);

        String day = "SAT";
        String kind = switch (day) {                       // switch EXPRESSION: produces a value
            case "SAT", "SUN" -> "weekend";
            default -> "weekday";
        };
        System.out.println(day + " is a " + kind + "; ternary: " + (count > 5 ? "big" : "small"));
        int[] numbers = {5, 3, 9};                         // arrays have a fixed size
        int largest = Integer.MIN_VALUE;
        for (int n : numbers) {                            // for-each loop
            largest = Math.max(largest, n);
        }
        System.out.println("largest in array: " + largest);
    }

    static void lesson2() {
        title("2. Classes, records, enums, interfaces");
        Counter a = new Counter();
        a.increment();
        a.increment();
        new Counter();
        System.out.println("counter value " + a.value() + ", counters created " + Counter.created());
        Person p = new Person("Amina", 30);
        System.out.println(p + " | " + p.greet() + " | equal records: " + p.equals(new Person("Amina", 30)));
        System.out.println("enum: " + Level.HIGH + " weight " + Level.HIGH.weight() + ", all " + List.of(Level.values()));
        Greeter anonymous = new Greeter() {                // anonymous class
            @Override
            public String name() {
                return "world";
            }
        };
        Greeter lambda = () -> "lambda";                   // a lambda works for an interface with ONE abstract method
        System.out.println(anonymous.greet() + " " + lambda.greet());
        try {
            new Person("Bad", -1);
        } catch (IllegalArgumentException e) {
            System.out.println("validation in record: " + e.getMessage());
        }
    }

    static void lesson3() {
        title("3. Sealed types, pattern matching, generics");
        List<Shape> shapes = List.of(new Circle(1), new Square(2), new Rectangle(2, 3));
        for (Shape s : shapes) {
            System.out.printf("%s area %.2f%n", s, area(s));
        }
        Object thing = "text";
        if (thing instanceof String s && s.length() > 2) {  // instanceof pattern: no cast needed
            System.out.println("it is a String of length " + s.length());
        }
        System.out.println("biggest number " + biggest(List.of(3, 9, 4)) + ", biggest word " + biggest(List.of("pear", "apple")));
        Optional<String> maybe = Optional.of("value");     // Optional: "maybe nothing" without null
        System.out.println(maybe.map(String::toUpperCase).orElse("none") + " / " + Optional.empty().isPresent());
    }

    static void lesson4() {
        title("4. Collections and streams");
        List<String> names = new ArrayList<>(List.of("Zed", "amy", "Bob", "amy"));
        names.sort(String.CASE_INSENSITIVE_ORDER);
        System.out.println("list " + names + ", set " + new java.util.TreeSet<>(names));
        Map<String, Integer> lengths = new java.util.TreeMap<>();
        for (String n : names) {
            lengths.merge(n.toLowerCase(), 1, Integer::sum);   // count occurrences
        }
        System.out.println("map " + lengths);
        List<Integer> squares = IntStream.rangeClosed(1, 6).boxed()
                .filter(n -> n % 2 == 0)                   // keep evens
                .map(n -> n * n)                           // square them
                .toList();
        System.out.println("streams: " + squares + " sum " + squares.stream().mapToInt(Integer::intValue).sum());
        Map<Integer, List<String>> byLength = names.stream().collect(Collectors.groupingBy(String::length));
        System.out.println("groupingBy length: " + byLength);
        Function<Integer, Integer> doubler = n -> n * 2;
        System.out.println("function composition: " + doubler.andThen(n -> n + 1).apply(5));
    }

    static void lesson5() {
        title("5. Strings and text blocks");
        String log = """
                192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] "GET /api/products HTTP/1.1" 200 512 9
                """;                                       // text block: multi-line, quotes need no escaping
        String[] parts = log.trim().split(" ");
        System.out.println("fields: " + parts.length + ", method " + parts[5].substring(1) + ", status " + parts[8]);
        StringBuilder sb = new StringBuilder();            // build text in a loop without creating many Strings
        for (int i = 0; i < 3; i++) {
            sb.append(i).append(',');
        }
        System.out.println(sb + " | " + String.format("%,d items, %.1f%%", 1234567, 99.5) + " | " + "a-b".replace('-', '+'));
        System.out.println("equals vs ==: " + "x".equals(new String("x")) + " " + ("x" == new String("x")));
    }

    static void lesson6() {
        title("6. Exceptions and try-with-resources");
        for (String input : new String[]{"42", "-3", "abc"}) {
            try {
                System.out.println("parsed " + parsePositive(input));
            } catch (BadInputException e) {
                System.out.println("rejected: " + e.getMessage());
            } finally {
                System.out.print("");                      // finally always runs (cleanup goes here)
            }
        }
        try (Resource r1 = new Resource("A"); Resource r2 = new Resource("B")) {
            System.out.println("  using " + r1.name + " and " + r2.name + ", sum " + sum(1, 2, 3));
        }                                                  // closes B then A
    }

    static void lesson7() throws InterruptedException {
        title("7. Threads (the basics)");
        Thread t = new Thread(() -> System.out.println("  hello from " + Thread.currentThread().getName()), "worker-1");
        t.start();                                         // start() runs it in parallel
        t.join();                                          // join() waits until it has finished
        System.out.println("  main continues after join");
    }

    static void lesson8() throws Exception {
        title("8. ExecutorService and Future (a thread pool)");
        ExecutorService pool = Executors.newFixedThreadPool(3);
        try {
            List<Callable<Integer>> jobs = new ArrayList<>();
            for (int i = 1; i <= 5; i++) {
                final int n = i;                           // lambdas may only use effectively final variables
                jobs.add(() -> n * n);                     // Callable returns a value (Runnable does not)
            }
            int total = 0;
            for (Future<Integer> f : pool.invokeAll(jobs)) {
                total += f.get();                          // get() waits for that result
            }
            System.out.println("  sum of squares via pool: " + total);
        } finally {
            pool.shutdown();                               // always shut a pool down or the program never exits
        }
    }

    static void lesson9() {
        title("9. CompletableFuture (chaining async steps)");
        CompletableFuture<Integer> price = CompletableFuture.supplyAsync(() -> 100);
        CompletableFuture<Integer> rate = CompletableFuture.supplyAsync(() -> 2);
        // Wait for both, combine, then format. Errors can be handled with exceptionally(...).
        String result = price.thenCombine(rate, (p, r) -> p * r).thenApply(v -> "total " + v)
                .exceptionally(e -> "failed").join();
        System.out.println("  " + result);
    }

    static void lesson10() {
        title("10. Virtual threads (Java 21)");
        // Each task gets its own very cheap thread. Perfect for tasks that mostly WAIT (network, disk).
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<String>> futures = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                final int n = i;
                futures.add(executor.submit(() -> {
                    Thread.sleep(50);                      // waiting does not block an operating-system thread
                    return "task " + n + " virtual=" + Thread.currentThread().isVirtual();
                }));
            }
            for (Future<String> f : futures) {
                try {
                    System.out.println("  " + f.get());
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
        }                                                  // close() waits for all tasks
        System.out.println("  10,000 virtual threads is fine; 10,000 platform threads would exhaust memory.");
    }

    static void lesson11() throws InterruptedException {
        title("11. Shared counters: the race condition");
        int threads = 4;
        int perThread = 100_000;
        int[] unsafe = {0};                                // plain ++ is read-modify-write: updates get lost
        AtomicLong atomic = new AtomicLong();              // one atomic operation: always correct
        LongAdder adder = new LongAdder();                 // like atomic, faster under heavy contention
        List<Thread> list = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            Thread thread = new Thread(() -> {
                for (int i = 0; i < perThread; i++) {
                    unsafe[0]++;
                    atomic.incrementAndGet();
                    adder.increment();
                }
            });
            list.add(thread);
            thread.start();
        }
        for (Thread t : list) {
            t.join();
        }
        System.out.println("  expected " + threads * perThread + " | plain int " + unsafe[0]
                + " (can be too small on a multi-core PC) | AtomicLong " + atomic.get() + " | LongAdder " + adder.sum());
        System.out.println("  The log analyzer avoids the problem entirely: each worker has its own counters, merged at the end.");
    }

    static void lesson12() throws InterruptedException {
        title("12. ConcurrentHashMap");
        Map<String, LongAdder> hits = new ConcurrentHashMap<>();   // safe for many threads without extra locking
        ExecutorService pool = Executors.newFixedThreadPool(4);
        for (int i = 0; i < 1000; i++) {
            final String route = i % 3 == 0 ? "/a" : "/b";
            pool.submit(() -> hits.computeIfAbsent(route, k -> new LongAdder()).increment());   // atomic "create if missing"
        }
        pool.shutdown();
        pool.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS);
        System.out.println("  /a=" + hits.get("/a").sum() + " /b=" + hits.get("/b").sum() + " (total 1000)");
    }

    static void lesson13() throws InterruptedException {
        title("13. Locks and semaphores");
        ReentrantLock lock = new ReentrantLock();
        int[] shared = {0};
        Runnable task = () -> {
            for (int i = 0; i < 50_000; i++) {
                lock.lock();                               // only one thread at a time inside
                try {
                    shared[0]++;
                } finally {
                    lock.unlock();                         // ALWAYS unlock in finally
                }
            }
        };
        Thread a = new Thread(task);
        Thread b = new Thread(task);
        a.start();
        b.start();
        a.join();
        b.join();
        System.out.println("  with a lock: " + shared[0] + " (expected 100000)");

        Semaphore permits = new Semaphore(2);              // at most 2 at a time: used to cap memory in VirtualThreadStrategy
        permits.acquire();
        permits.acquire();
        System.out.println("  third acquire possible right now? " + permits.tryAcquire());
        permits.release(2);
    }

    static void lesson14() throws InterruptedException {
        title("14. CountDownLatch (wait until N things are done)");
        CountDownLatch done = new CountDownLatch(3);
        for (int i = 0; i < 3; i++) {
            new Thread(done::countDown).start();           // method reference instead of a lambda
        }
        done.await();
        System.out.println("  all 3 workers finished. End of tour.");
    }
}
