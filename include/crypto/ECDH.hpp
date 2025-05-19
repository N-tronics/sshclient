#pragma once

#include <TypeDefs.hpp>

namespace crypto {

namespace ecdh {
    
    typedef struct Curve {
        num_t a, b, p;
        Curve(num_t a, num_t b, num_t p) : a(a), b(b), p(p) {}
    } Curve;

    class Point {
    public:
        num_t x, y;
        Curve c;
        Point(num_t x, num_t y, Curve c) : x(x) , y(y), c(c) {}
        Point(Curve c) : c(c) {}

        Point operator+(Point const &q);
        friend Point operator*(const num_t &k, const Point &P);
    };
    std::ostream& operator<<(std::ostream& os, const Point& p);
    
    extern Curve brainpoolP256r1;
    extern Point brainpoolP256r1Generator;

} // namespace ecdh

} // namespace crypto
