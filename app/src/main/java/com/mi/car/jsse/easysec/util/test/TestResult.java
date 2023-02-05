package com.mi.car.jsse.easysec.util.test;

public interface TestResult {
    Throwable getException();

    boolean isSuccessful();

    String toString();
}
