package com.mi.car.jsse.easysec.util.test;

import com.mi.car.jsse.easysec.util.Strings;

public class SimpleTestResult implements TestResult {
    private static final String SEPARATOR = Strings.lineSeparator();
    private Throwable exception;
    private String message;
    private boolean success;

    public SimpleTestResult(boolean success2, String message2) {
        this.success = success2;
        this.message = message2;
    }

    public SimpleTestResult(boolean success2, String message2, Throwable exception2) {
        this.success = success2;
        this.message = message2;
        this.exception = exception2;
    }

    public static TestResult successful(Test test, String message2) {
        return new SimpleTestResult(true, test.getName() + ": " + message2);
    }

    public static TestResult failed(Test test, String message2) {
        return new SimpleTestResult(false, test.getName() + ": " + message2);
    }

    public static TestResult failed(Test test, String message2, Throwable t) {
        return new SimpleTestResult(false, test.getName() + ": " + message2, t);
    }

    public static TestResult failed(Test test, String message2, Object expected, Object found) {
        return failed(test, message2 + SEPARATOR + "Expected: " + expected + SEPARATOR + "Found   : " + found);
    }

    public static String failedMessage(String algorithm, String testName, String expected, String actual) {
        StringBuffer sb = new StringBuffer(algorithm);
        sb.append(" failing ").append(testName);
        sb.append(SEPARATOR).append("    expected: ").append(expected);
        sb.append(SEPARATOR).append("    got     : ").append(actual);
        return sb.toString();
    }

    @Override // com.mi.car.jsse.easysec.util.test.TestResult
    public boolean isSuccessful() {
        return this.success;
    }

    @Override // com.mi.car.jsse.easysec.util.test.TestResult
    public String toString() {
        return this.message;
    }

    @Override // com.mi.car.jsse.easysec.util.test.TestResult
    public Throwable getException() {
        return this.exception;
    }
}
