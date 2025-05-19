#pragma once

#include <TypeDefs.hpp>

Bytes numToBytes(num_t n, size_t bytes = 32);
num_t bytesToNum(Bytes bytes);

num_t powMod(num_t a, num_t b, num_t n);
num_t modularInverse(num_t a, num_t n);
