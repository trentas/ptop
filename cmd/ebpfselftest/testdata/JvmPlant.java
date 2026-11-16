// The jvmpause case's planted workload (#189), run in source-file mode
// (`java JvmPlant.java`), so the selftest needs a JDK and no build step.
//
// It plants forced full collections, each one a safepoint, and reports what
// the JVM itself counted over the same span: its safepoints and their time
// (HotSpot's own sun.rt.safepoints counters, read through the internal
// HotspotRuntimeMBean, hence the --add-exports), its collections (the standard
// GC MXBeans), and its own wall clock around each System.gc().
//
// Protocol on stdin/stdout:
//   -> "ready"                       live set allocated, everything warmed up
//   <- "go"
//   -> "done <safepoints> <safepoint_ms> <collections> <gc_wall_ns>"
//   <- EOF                           exit
//
// Nothing the window runs is run for the first time inside it, and the window
// allocates next to nothing, so the only safepoints and collections in it are
// the planted ones.

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.util.List;
import java.util.Random;

import sun.management.HotspotRuntimeMBean;
import sun.management.ManagementFactoryHelper;

public class JvmPlant {
    // A live set the collector has to trace and move, so that a full
    // collection takes milliseconds, not microseconds, and its length can be
    // checked against the program's own clock.
    static long[][] live;

    public static void main(String[] args) throws Exception {
        int cycles = Integer.parseInt(args[0]);
        int objects = Integer.parseInt(args[1]);
        Random r = new Random(Long.parseLong(args[2]));

        live = new long[objects][];
        for (int i = 0; i < objects; i++) {
            live[i] = new long[4];
        }
        HotspotRuntimeMBean rt = ManagementFactoryHelper.getHotspotRuntimeMBean();
        List<GarbageCollectorMXBean> gcs = ManagementFactory.getGarbageCollectorMXBeans();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

        // Warm up every call the window makes.
        rt.getSafepointCount();
        rt.getTotalSafepointTime();
        rt.getSafepointSyncTime();
        collections(gcs);
        System.nanoTime();
        Thread.sleep(1);
        new StringBuilder("x").append(1L).toString();

        System.out.println("ready");
        if (!"go".equals(in.readLine())) {
            return;
        }

        long sp0 = rt.getSafepointCount();
        long ms0 = rt.getTotalSafepointTime() + rt.getSafepointSyncTime();
        long gc0 = collections(gcs);
        long wall = 0;
        for (int i = 0; i < cycles; i++) {
            // No period: a sampler or a timer at a nearby fixed rate would
            // otherwise see the cycle at one phase.
            Thread.sleep(5 + r.nextInt(30));
            long t = System.nanoTime();
            System.gc();
            wall += System.nanoTime() - t;
        }
        long sp1 = rt.getSafepointCount();
        long ms1 = rt.getTotalSafepointTime() + rt.getSafepointSyncTime();
        long gc1 = collections(gcs);

        System.out.println(new StringBuilder("done ")
                .append(sp1 - sp0).append(' ')
                .append(ms1 - ms0).append(' ')
                .append(gc1 - gc0).append(' ')
                .append(wall).toString());
        in.readLine();
    }

    static long collections(List<GarbageCollectorMXBean> gcs) {
        long n = 0;
        for (GarbageCollectorMXBean b : gcs) {
            n += Math.max(0, b.getCollectionCount());
        }
        return n;
    }
}
