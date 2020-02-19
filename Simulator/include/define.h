#ifndef __DEFINE_H__
#define __DEFINE_H__

/**sketch configuration*/
#define SKETCH_ENABLE 1 
#define SKETCH_DEPTH 4
#define SKETCH_WIDTH (2<<20)
#define FP_SIZE (6)
// if use UBC fingerprint, FP_SIZE = 5

#define ULL unsigned long long /**just for  */
#define S2US (1000 * 1000)  /**transform second to microsecond */ 
#define BUFFER_SIZE (128 * 1024 * 1024) /**the read buffer size */
#define CIPHER_SIZE (32)
#define TEST_TIME (10)
#define B_TO_GB (1024 * 1024 * 1024)
#define B_TO_MB (1024 * 1024)

/**for the setting of dictatory */
#define RESULT_DIR "./result/"

/**for the option of printing ciphertext */
#define FULL_CIPHER_TEXT 1

#define ACCURACY (500)
#define SEGMENT_ENABLE 0
#define LOCAL_TEC 1
#define GLOBAL_TEC 2

/**for debug */
#define CURRENT_LIEN __LINE__
#define FILE_NAME __FILE__

#endif // !1

