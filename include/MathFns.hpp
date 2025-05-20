#pragma once

#include <TypeDefs.hpp>

Bytes numToBytes(num_t n, size_t bytes = 32);
num_t bytesToNum(const Bytes& bytes);

num_t powMod(num_t a, num_t b, num_t p);
num_t modularInverse(num_t a, num_t m);
