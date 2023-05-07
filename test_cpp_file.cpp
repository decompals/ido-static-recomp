extern void function_func(void);

class BoringClass {
private:
    int a;
    int b;
    float c;
    double d;
    short e;

public:
    BoringClass(void) {
        a = 0;
        b = 0;
        c = 0;
        d = 0;
        e = 0;
    }
    BoringClass(int arg) {
        a = arg;
        b = arg;
        c = arg;
        d = arg;
        e = arg;
    }
    BoringClass(int arg, int arg1) {
        a = arg;
        b = arg;
        c = arg1;
        d = arg1;
        e = arg1;
    }
    BoringClass(int arg, int arg1, int arg2, int arg3) {
        a = arg;
        b = arg1;
        c = arg2;
        d = arg3;
        e = arg;
    }

    BoringClass(float arg) {
        a = arg;
        b = arg;
        c = arg;
        d = arg;
        e = arg;
    }
    BoringClass(float arg, float arg1) {
        a = arg;
        b = arg;
        c = arg1;
        d = arg1;
        e = arg1;
    }

    BoringClass(double arg) {
        a = arg;
        b = arg;
        c = arg;
        d = arg;
        e = arg;
    }
    BoringClass(double arg, double arg1) {
        a = arg;
        b = arg;
        c = arg1;
        d = arg1;
        e = arg1;
    }

    BoringClass(int arg, double arg1, short arg2, float arg3) {
        a = arg;
        b = arg1;
        c = arg2;
        d = arg3;
        e = arg;
    }

    ~BoringClass(void) {
        function_func();
    }


    void two(void) {
        a *= 2;
        b *= 2;
        c *= 2;
        d *= 2;
        e *= 2;
    }

    int two_again(void) {
        a *= 2;
        b *= 2;
        c *= 2;
        d *= 2;
        e *= 2;

        return a;
    }

    void number(float arg) {
        a *= arg;
        b *= arg;
        c *= arg;
        d *= arg;
        e *= arg;
    }

    float number_again(float arg) {
        a *= arg;
        b *= arg;
        c *= arg;
        d *= arg;
        e *= arg;

        return a;
    }
};
