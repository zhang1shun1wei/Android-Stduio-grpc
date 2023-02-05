package com.mi.car.jsse.easysec.asn1;

public class ASN1EncodableVector {
    private static final int DEFAULT_CAPACITY = 10;
    static final ASN1Encodable[] EMPTY_ELEMENTS = new ASN1Encodable[0];
    private boolean copyOnWrite;
    private int elementCount;
    private ASN1Encodable[] elements;

    public ASN1EncodableVector() {
        this(10);
    }

    public ASN1EncodableVector(int initialCapacity) {
        if (initialCapacity < 0) {
            throw new IllegalArgumentException("'initialCapacity' must not be negative");
        }
        this.elements = initialCapacity == 0 ? EMPTY_ELEMENTS : new ASN1Encodable[initialCapacity];
        this.elementCount = 0;
        this.copyOnWrite = false;
    }

    public void add(ASN1Encodable element) {
        if (element == null) {
            throw new NullPointerException("'element' cannot be null");
        }
        int capacity = this.elements.length;
        int minCapacity = this.elementCount + 1;
        if ((minCapacity > capacity) || this.copyOnWrite) {
            reallocate(minCapacity);
        }
        this.elements[this.elementCount] = element;
        this.elementCount = minCapacity;
    }

    public void addAll(ASN1Encodable[] others) {
        if (others == null) {
            throw new NullPointerException("'others' cannot be null");
        }
        doAddAll(others, "'others' elements cannot be null");
    }

    public void addAll(ASN1EncodableVector other) {
        if (other == null) {
            throw new NullPointerException("'other' cannot be null");
        }
        doAddAll(other.elements, "'other' elements cannot be null");
    }

    private void doAddAll(ASN1Encodable[] others, String nullMsg) {
        boolean z = true;
        int otherElementCount = others.length;
        if (otherElementCount >= 1) {
            int capacity = this.elements.length;
            int minCapacity = this.elementCount + otherElementCount;
            if (minCapacity <= capacity) {
                z = false;
            }
            if (z || this.copyOnWrite) {
                reallocate(minCapacity);
            }
            int i = 0;
            do {
                ASN1Encodable otherElement = others[i];
                if (otherElement == null) {
                    throw new NullPointerException(nullMsg);
                }
                this.elements[this.elementCount + i] = otherElement;
                i++;
            } while (i < otherElementCount);
            this.elementCount = minCapacity;
        }
    }

    public ASN1Encodable get(int i) {
        if (i < this.elementCount) {
            return this.elements[i];
        }
        throw new ArrayIndexOutOfBoundsException(i + " >= " + this.elementCount);
    }

    public int size() {
        return this.elementCount;
    }

    /* access modifiers changed from: package-private */
    public ASN1Encodable[] copyElements() {
        if (this.elementCount == 0) {
            return EMPTY_ELEMENTS;
        }
        ASN1Encodable[] copy = new ASN1Encodable[this.elementCount];
        System.arraycopy(this.elements, 0, copy, 0, this.elementCount);
        return copy;
    }

    /* access modifiers changed from: package-private */
    public ASN1Encodable[] takeElements() {
        if (this.elementCount == 0) {
            return EMPTY_ELEMENTS;
        }
        if (this.elements.length == this.elementCount) {
            this.copyOnWrite = true;
            return this.elements;
        }
        ASN1Encodable[] copy = new ASN1Encodable[this.elementCount];
        System.arraycopy(this.elements, 0, copy, 0, this.elementCount);
        return copy;
    }

    private void reallocate(int minCapacity) {
        ASN1Encodable[] copy = new ASN1Encodable[Math.max(this.elements.length, (minCapacity >> 1) + minCapacity)];
        System.arraycopy(this.elements, 0, copy, 0, this.elementCount);
        this.elements = copy;
        this.copyOnWrite = false;
    }

    static ASN1Encodable[] cloneElements(ASN1Encodable[] elements2) {
        return elements2.length < 1 ? EMPTY_ELEMENTS : (ASN1Encodable[]) elements2.clone();
    }
}
