package com.mi.car.jsse.easysec.pqc.math.ntru.euclid;

public class IntEuclidean {
    public int gcd;
    public int x;
    public int y;

    private IntEuclidean() {
    }

    public static IntEuclidean calculate(int a, int b) {
        int x2 = 0;
        int lastx = 1;
        int y2 = 1;
        int lasty = 0;
        while (b != 0) {
            int quotient = a / b;
            a = b;
            b = a % b;
            x2 = lastx - (quotient * x2);
            lastx = x2;
            y2 = lasty - (quotient * y2);
            lasty = y2;
        }
        IntEuclidean result = new IntEuclidean();
        result.x = lastx;
        result.y = lasty;
        result.gcd = a;
        return result;
    }
}
