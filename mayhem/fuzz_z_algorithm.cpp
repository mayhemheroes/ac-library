#include <stdint.h>
#include <stdio.h>
#include <climits>
#include "atcoder/string"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();

    atcoder::z_algorithm(str);

    return 0;
}
