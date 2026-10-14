import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

// Build-time coverage instrumentation for Eclair.
//
// Rewrites the JARs in a directory in place, inserting EclairSanCov.edge(id)
// probes into every non-abstract, non-native method of the instrumented
// packages, and prints the probe count (TARGET_MAP_SIZE) to stdout. Doing this
// at build time keeps ASM out of the fuzzed JVM: a load-time agent re-ran the
// transform on every execution for classes first loaded after the snapshot.
//
// Each method gets a probe at entry, one after each conditional jump (the
// fall-through arc) and one at each label (block entry, covering taken arcs).
// IDs are sequential over classes sorted by name, then bytecode order, so they
// are stable across builds of the same JARs.
//
// Usage: java -cp eclair-sancov.jar EclairInstrumenter <lib-dir>
public class EclairInstrumenter {

  static final String[] INSTRUMENTED_PREFIXES = {
      "fr/acinq/", // Eclair, bitcoin-lib, bitcoin-kmp, secp256k1-kmp
      "scala/",    // collections, Option, pattern matching runtime
      "scodec/",   // binary codec for BOLT wire message serialization
  };

  // Superclass of every class in the JARs, so NonLoadingClassWriter can
  // compute frames without loading Eclair's classes.
  static final Map<String, String> superclassMap = new HashMap<>();

  public static void main(String[] args) throws IOException {
    if (args.length != 1) {
      System.err.println("Usage: EclairInstrumenter <lib-dir>");
      System.exit(1);
    }

    List<Path> jars;
    try (Stream<Path> files = Files.list(Path.of(args[0]))) {
      jars = files.filter(p -> p.toString().endsWith(".jar")).sorted().toList();
    }

    // Sorted by class name so IDs don't depend on JAR order.
    TreeMap<String, byte[]> classes = new TreeMap<>();
    Set<Path> jarsToRewrite = new HashSet<>();
    for (Path jar : jars) {
      if (readJar(jar, classes)) {
        jarsToRewrite.add(jar);
      }
    }

    int[] nextId = {0};
    Map<String, byte[]> instrumented = new HashMap<>();
    for (Map.Entry<String, byte[]> e : classes.entrySet()) {
      instrumented.put(e.getKey(), instrument(e.getValue(), nextId));
    }
    if (nextId[0] > EclairSanCov.SCRATCH_MAP_SIZE) {
      throw new IllegalStateException("eclair-sancov: " + nextId[0] +
                                      " probes exceed SCRATCH_MAP_SIZE");
    }

    for (Path jar : jarsToRewrite) {
      rewriteJar(jar, instrumented);
    }

    System.err.printf("eclair-sancov: %d probes in %d classes across %d JARs%n",
                      nextId[0], classes.size(), jarsToRewrite.size());
    System.out.println(nextId[0]);
  }

  static boolean shouldInstrument(String className) {
    for (String prefix : INSTRUMENTED_PREFIXES) {
      if (className.startsWith(prefix))
        return true;
    }
    return false;
  }

  // Returns the internal class name for a .class entry, or null otherwise.
  static String classNameOf(String entryName) {
    return entryName.endsWith(".class")
        ? entryName.substring(0, entryName.length() - 6)
        : null;
  }

  // Records every class's superclass and collects instrumented classes into
  // `classes`. Returns whether the JAR holds any instrumented class.
  static boolean readJar(Path jar, Map<String, byte[]> classes)
      throws IOException {
    boolean hasInstrumented = false;
    boolean signed = false;
    try (ZipFile zip = new ZipFile(jar.toFile())) {
      for (ZipEntry entry : Collections.list(zip.entries())) {
        String name = entry.getName();
        signed |= name.startsWith("META-INF/") && name.endsWith(".SF");
        String className = classNameOf(name);
        if (className == null) {
          continue;
        }
        byte[] bytecode = zip.getInputStream(entry).readAllBytes();
        String superName = new ClassReader(bytecode).getSuperName();
        if (superName != null) {
          superclassMap.put(className, superName);
        }
        if (!shouldInstrument(className)) {
          continue;
        }
        // Two copies would share probe IDs, so refuse rather than guess.
        if (classes.put(className, bytecode) != null) {
          throw new IllegalStateException(
              "eclair-sancov: duplicate class " + className + " in " + jar);
        }
        hasInstrumented = true;
      }
    }
    if (hasInstrumented && signed) {
      throw new IllegalStateException(
          "eclair-sancov: " + jar + " is signed; instrumenting it would fail " +
          "signature verification");
    }
    return hasInstrumented;
  }

  static byte[] instrument(byte[] bytecode, int[] nextId) {
    ClassReader reader = new ClassReader(bytecode);
    // Debug info stays in the output: libraries read class files back from the
    // JAR for reflection, and Eclair's json4s-based bitcoind RPC fails without
    // it. Probe positions come from a pass without it, so line-number labels
    // don't add probes.
    ClassNode withoutDebug = new ClassNode();
    reader.accept(withoutDebug, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    ClassNode full = new ClassNode();
    reader.accept(full, ClassReader.SKIP_FRAMES);

    for (int i = 0; i < full.methods.size(); i++) {
      MethodNode method = full.methods.get(i);
      if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0) {
        insertProbes(method, blockStarts(withoutDebug.methods.get(i)), nextId);
      }
    }

    // Probes change the stack depth where they are inserted, so frames are
    // recomputed.
    ClassWriter writer = new NonLoadingClassWriter(ClassWriter.COMPUTE_FRAMES);
    full.accept(writer);
    return writer.toByteArray();
  }

  // Indices of the instructions a label sits in front of. Without debug info,
  // every label is a branch target, exception handler or try range bound.
  static BitSet blockStarts(MethodNode method) {
    BitSet starts = new BitSet();
    int index = 0;
    for (AbstractInsnNode node : method.instructions) {
      if (node instanceof LabelNode) {
        starts.set(index);
      } else if (node.getOpcode() >= 0) {
        index++;
      }
    }
    return starts;
  }

  // Inserts edge() probes at method entry, after each conditional jump (the
  // fall-through arc) and after each block-start label (covering taken arcs),
  // taking IDs from the shared counter in bytecode order.
  static void insertProbes(MethodNode method, BitSet blockStarts,
                           int[] nextId) {
    InsnList insns = method.instructions;
    AbstractInsnNode[] original = insns.toArray();
    insns.insert(probe(nextId));
    int index = 0;
    for (AbstractInsnNode node : original) {
      if (node instanceof LabelNode && blockStarts.get(index)) {
        insns.insert(node, probe(nextId));
      } else if (node instanceof JumpInsnNode &&
                 node.getOpcode() != Opcodes.GOTO &&
                 node.getOpcode() != Opcodes.JSR) {
        insns.insert(node, probe(nextId));
      }
      if (node.getOpcode() >= 0) {
        index++;
      }
    }
  }

  // ldc id; invokestatic EclairSanCov.edge(I)V
  static InsnList probe(int[] nextId) {
    InsnList probe = new InsnList();
    probe.add(new LdcInsnNode(nextId[0]++));
    probe.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "EclairSanCov", "edge",
                                 "(I)V", false));
    return probe;
  }

  // Writes the JAR again with its instrumented classes replaced, keeping
  // every other entry and the entry order.
  static void rewriteJar(Path jar, Map<String, byte[]> instrumented)
      throws IOException {
    Path tmp = jar.resolveSibling(jar.getFileName() + ".tmp");
    try (ZipFile in = new ZipFile(jar.toFile());
         ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(tmp))) {
      for (ZipEntry entry : Collections.list(in.entries())) {
        String name = entry.getName();
        out.putNextEntry(new ZipEntry(name));
        String className = classNameOf(name);
        byte[] bytecode = className == null ? null : instrumented.get(className);
        if (bytecode != null) {
          out.write(bytecode);
        } else {
          in.getInputStream(entry).transferTo(out);
        }
        out.closeEntry();
      }
    }
    Files.move(tmp, jar, StandardCopyOption.REPLACE_EXISTING);
  }

  // Returns the superclass of an internal class name, falling back to the
  // JDK for classes outside the JARs.
  static String superOf(String type) {
    String s = superclassMap.get(type);
    if (s != null)
      return s;
    try {
      Class<?> c = Class.forName(type.replace('/', '.'), false, null);
      Class<?> p = c.getSuperclass();
      return p != null ? p.getName().replace('.', '/') : null;
    } catch (Exception e) {
      return null;
    }
  }

  // ClassWriter that resolves type hierarchies via superclassMap instead of
  // loading the classes, which aren't on this tool's classpath.
  static class NonLoadingClassWriter extends ClassWriter {

    NonLoadingClassWriter(int flags) {
      super(flags);
    }

    @Override
    protected String getCommonSuperClass(String type1, String type2) {
      Set<String> ancestors = new HashSet<>();
      for (String t = type1; t != null && ancestors.add(t); t = superOf(t))
        ;
      for (String t = type2; t != null; t = superOf(t))
        if (ancestors.contains(t))
          return t;
      return "java/lang/Object";
    }
  }
}
