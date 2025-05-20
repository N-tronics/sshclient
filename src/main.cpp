#include <iostream>
#include <string>

class A  {
protected:
    int a;
public:
    A(int a) : a(a) {}
    A() {}
    void print() {
        std::cout << a << std::endl;
    }
};

class B : public A {
private:
    A obj;
public:
    B() {}
    void setup() {
        obj = A(5);
    }
    void cout() {
        obj.print();
    }
};

int main() {
    B b;
    b.setup();
    b.cout();
}
