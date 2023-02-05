package com.mi.car.jsse.easysec.util.test;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.PrintStream;
import java.util.Enumeration;
import java.util.Vector;

public abstract class SimpleTest implements Test {
    @Override // com.mi.car.jsse.easysec.util.test.Test
    public abstract String getName();

    public abstract void performTest() throws Exception;

    private TestResult success() {
        return SimpleTestResult.successful(this, "Okay");
    }

    /* access modifiers changed from: protected */
    public void fail(String message) {
        throw new TestFailedException(SimpleTestResult.failed(this, message));
    }

    /* access modifiers changed from: protected */
    public void isTrue(boolean value) {
        if (!value) {
            throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
        }
    }

    /* access modifiers changed from: protected */
    public void isTrue(String message, boolean value) {
        if (!value) {
            throw new TestFailedException(SimpleTestResult.failed(this, message));
        }
    }

    /* access modifiers changed from: protected */
    public void isEquals(Object a, Object b) {
        if (!a.equals(b)) {
            throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
        }
    }

    /* access modifiers changed from: protected */
    public void isEquals(int a, int b) {
        if (a != b) {
            throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
        }
    }

    /* access modifiers changed from: protected */
    public void isEquals(long a, long b) {
        if (a != b) {
            throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
        }
    }

    /* access modifiers changed from: protected */
    public void isEquals(boolean a, boolean b) {
        if (a != b) {
            throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
        }
    }

    /* access modifiers changed from: protected */
    public void isEquals(String message, boolean a, boolean b) {
        if (a != b) {
            throw new TestFailedException(SimpleTestResult.failed(this, message));
        }
    }

    /* access modifiers changed from: protected */
    public void isEquals(String message, long a, long b) {
        if (a != b) {
            throw new TestFailedException(SimpleTestResult.failed(this, message));
        }
    }

    /* access modifiers changed from: protected */
    public void isEquals(String message, Object a, Object b) {
        if (a != null || b != null) {
            if (a == null) {
                throw new TestFailedException(SimpleTestResult.failed(this, message));
            } else if (b == null) {
                throw new TestFailedException(SimpleTestResult.failed(this, message));
            } else if (!a.equals(b)) {
                throw new TestFailedException(SimpleTestResult.failed(this, message));
            }
        }
    }

    /* access modifiers changed from: protected */
    public boolean areEqual(byte[][] left, byte[][] right) {
        if (left == null && right == null) {
            return true;
        }
        if (left == null || right == null) {
            return false;
        }
        if (left.length != right.length) {
            return false;
        }
        for (int t = 0; t < left.length; t++) {
            if (!areEqual(left[t], right[t])) {
                return false;
            }
        }
        return true;
    }

    /* access modifiers changed from: protected */
    public void fail(String message, Throwable throwable) {
        throw new TestFailedException(SimpleTestResult.failed(this, message, throwable));
    }

    /* access modifiers changed from: protected */
    public void fail(String message, Object expected, Object found) {
        throw new TestFailedException(SimpleTestResult.failed(this, message, expected, found));
    }

    /* access modifiers changed from: protected */
    public boolean areEqual(byte[] a, byte[] b) {
        return Arrays.areEqual(a, b);
    }

    /* access modifiers changed from: protected */
    public boolean areEqual(byte[] a, int aFromIndex, int aToIndex, byte[] b, int bFromIndex, int bToIndex) {
        return Arrays.areEqual(a, aFromIndex, aToIndex, b, bFromIndex, bToIndex);
    }

    @Override // com.mi.car.jsse.easysec.util.test.Test
    public TestResult perform() {
        try {
            performTest();
            return success();
        } catch (TestFailedException e) {
            return e.getResult();
        } catch (Exception e2) {
            return SimpleTestResult.failed(this, "Exception: " + e2, e2);
        }
    }

    public static void runTest(Test test) {
        runTest(test, System.out);
    }

    public static void runTest(Test test, PrintStream out) {
        TestResult result = test.perform();
        if (result.getException() != null) {
            result.getException().printStackTrace(out);
        }
        out.println(result);
    }

    public static void runTests(Test[] tests) {
        runTests(tests, System.out);
    }

    public static void runTests(Test[] tests, PrintStream out) {
        Vector failures = new Vector();
        for (int i = 0; i != tests.length; i++) {
            TestResult result = tests[i].perform();
            if (!result.isSuccessful()) {
                failures.addElement(result);
            }
            if (result.getException() != null) {
                result.getException().printStackTrace(out);
            }
            out.println(result);
        }
        out.println("-----");
        if (failures.isEmpty()) {
            out.println("All tests successful.");
            return;
        }
        out.println("Completed with " + failures.size() + " FAILURES:");
        Enumeration e = failures.elements();
        while (e.hasMoreElements()) {
            System.out.println("=>  " + ((TestResult) e.nextElement()));
        }
    }
}
