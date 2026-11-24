import java.lang.reflect.Field;
import sun.misc.Unsafe;

// Runtime for the coverage probes EclairInstrumenter compiles into Eclair's
// JARs. Each probe calls edge(id), which bumps byte `id` of the AFL coverage
// map. The map is attached on the first probe, during Eclair's startup and so
// before the Nyx snapshot.
public final class EclairSanCov {

  // Size of the scratch map probes write to when no AFL map is shared (e.g.
  // smitebot reproduce). EclairInstrumenter fails the build if IDs exceed it.
  static final int SCRATCH_MAP_SIZE = 1 << 24;

  // Unsafe.getByte/putByte avoid the bounds check and address field load that
  // DirectByteBuffer.get/put perform on every call.
  private static final Unsafe UNSAFE = getUnsafe();

  // Base address of the coverage map, final so the JIT can fold it into each
  // probe.
  private static final long MAP_ADDR = mapCoverage();

  private EclairSanCov() {}

  // Records a hit on probe `edgeId`, which is always in [0, probe count).
  public static void edge(int edgeId) {
    long addr = MAP_ADDR + edgeId;
    UNSAFE.putByte(addr, (byte)(UNSAFE.getByte(addr) + 1));
  }

  private static long mapCoverage() {
    String shmId = System.getenv("__AFL_SHM_ID");
    if (shmId == null) {
      // The JARs are always instrumented, so probes need memory to write to
      // even when nothing reads it.
      return UNSAFE.allocateMemory(SCRATCH_MAP_SIZE);
    }
    System.loadLibrary("eclair-sancov");
    long addr = mapShmAddr(Integer.parseInt(shmId));
    if (addr == 0) {
      throw new IllegalStateException("eclair-sancov: mapShmAddr failed");
    }
    return addr;
  }

  // Attaches the AFL shared memory segment via shmat and returns its address.
  // Implemented in shmutil.c via JNI.
  private static native long mapShmAddr(int shmId);

  private static Unsafe getUnsafe() {
    try {
      Field f = Unsafe.class.getDeclaredField("theUnsafe");
      f.setAccessible(true);
      return (Unsafe)f.get(null);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("eclair-sancov: failed to get Unsafe", e);
    }
  }
}
