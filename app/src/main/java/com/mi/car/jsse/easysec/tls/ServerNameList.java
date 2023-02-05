package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

public class ServerNameList {
    protected Vector serverNameList;

    public ServerNameList(Vector serverNameList2) {
        if (serverNameList2 == null) {
            throw new NullPointerException("'serverNameList' cannot be null");
        }
        this.serverNameList = serverNameList2;
    }

    public Vector getServerNameList() {
        return this.serverNameList;
    }

    public void encode(OutputStream output) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        short[] nameTypesSeen = TlsUtils.EMPTY_SHORTS;
        for (int i = 0; i < this.serverNameList.size(); i++) {
            ServerName entry = (ServerName) this.serverNameList.elementAt(i);
            nameTypesSeen = checkNameType(nameTypesSeen, entry.getNameType());
            if (nameTypesSeen == null) {
                throw new TlsFatalAlert((short) 80);
            }
            entry.encode(buf);
        }
        TlsUtils.checkUint16(buf.size());
        TlsUtils.writeUint16(buf.size(), output);
        Streams.writeBufTo(buf, output);
    }

    public static ServerNameList parse(InputStream input) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(TlsUtils.readOpaque16(input, 1));
        short[] nameTypesSeen = TlsUtils.EMPTY_SHORTS;
        Vector server_name_list = new Vector();
        while (buf.available() > 0) {
            ServerName entry = ServerName.parse(buf);
            nameTypesSeen = checkNameType(nameTypesSeen, entry.getNameType());
            if (nameTypesSeen == null) {
                throw new TlsFatalAlert((short) 47);
            }
            server_name_list.addElement(entry);
        }
        return new ServerNameList(server_name_list);
    }

    private static short[] checkNameType(short[] nameTypesSeen, short nameType) {
        if (Arrays.contains(nameTypesSeen, nameType)) {
            return null;
        }
        return Arrays.append(nameTypesSeen, nameType);
    }
}
