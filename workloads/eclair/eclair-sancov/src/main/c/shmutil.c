#include <jni.h>
#include <stdio.h>
#include <sys/shm.h>

// JNI implementation of EclairSanCov.mapShmAddr(int shmId).
//
// Attaches to the AFL shared memory segment identified by shmId via shmat()
// and returns the raw pointer as a jlong. The Java side uses sun.misc.Unsafe
// to read/write coverage counters directly at this address, avoiding the bounds
// check and field load overhead of DirectByteBuffer.get/put.
//
// Called once from EclairSanCov's static initializer, on the first probe.
JNIEXPORT jlong JNICALL Java_EclairSanCov_mapShmAddr(JNIEnv *env, jclass cls,
                                                     jint shmId) {
  void *ptr = shmat((int)shmId, NULL, 0);
  if (ptr == (void *)-1) {
    perror("eclair-sancov: shmat");
    return 0;
  }

  return (jlong)ptr;
}
