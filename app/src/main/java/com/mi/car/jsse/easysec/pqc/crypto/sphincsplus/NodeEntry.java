package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

class NodeEntry {
    final int nodeHeight;
    final byte[] nodeValue;

    NodeEntry(byte[] nodeValue2, int nodeHeight2) {
        this.nodeValue = nodeValue2;
        this.nodeHeight = nodeHeight2;
    }
}
