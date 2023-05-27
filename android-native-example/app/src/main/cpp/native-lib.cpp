#include <jni.h>
#include <string>

const char key[] = "DDL202205122359";
const char secret[] = {0x2, 0x8, 0xd, 0x75, 0x4b, 0x65, 0x1, 0x1, 0x76, 0x1, 0x7f, 0x1, 0x6c, 0x7, 0x66, 0x14, 0x2b, 0x1e, 0x77, 0x6f, 0x7e, 0x72, 0x72, 0xd, 0x4c};

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_lab7_1warmup_MainActivity_Check(
        JNIEnv* env, jobject, jstring flag) {
    if ( (*env).GetStringUTFLength(flag) == 25 ) {
        const char *str = (*env).GetStringUTFChars(flag, 0);
        for (int i = 0; i < 25; i++) {
            if ((str[i] ^ key[i%15]) != secret[i]) {
                return JNI_FALSE;
            }
        }
        return JNI_TRUE;
    }
    return JNI_FALSE;
}