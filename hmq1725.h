#ifndef HMQ1725_H
#define HMQ1725_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void hmq1725_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
