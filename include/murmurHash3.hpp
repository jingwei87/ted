#ifndef GENERALDEDUPSYSTEM_MURMURHASH3_HPP_
#define GENERALDEDUPSYSTEM_MURMURHASH3_HPP_

#include <bits/stdc++.h>

//-----------------------------------------------------------------------------

void MurmurHash3_x86_32(const void* key, int len, uint32_t seed, void* out);

void MurmurHash3_x86_128(const void* key, int len, uint32_t seed, void* out);

void MurmurHash3_x64_128(const void* key, int len, uint32_t seed, void* out);

//-----------------------------------------------------------------------------

#endif // GENERALDEDUPSYSTEM_MURMURHASH3_HPP_
