package com.mi.car.jsse.easysec.i18n.filter;

import com.mi.car.jsse.easysec.crypto.agreement.jpake.JPAKEParticipant;

public class HTMLFilter implements Filter {
    @Override // com.mi.car.jsse.easysec.i18n.filter.Filter
    public String doFilter(String input) {
        StringBuffer buf = new StringBuffer(input);
        int i = 0;
        while (i < buf.length()) {
            switch (buf.charAt(i)) {
                case '\"':
                    buf.replace(i, i + 1, "&#34");
                    break;
                case '#':
                    buf.replace(i, i + 1, "&#35");
                    break;
                case '$':
                case '*':
                case ',':
                case '.':
                case '/':
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                case ':':
                case '=':
                default:
                    i -= 3;
                    break;
                case '%':
                    buf.replace(i, i + 1, "&#37");
                    break;
                case '&':
                    buf.replace(i, i + 1, "&#38");
                    break;
                case '\'':
                    buf.replace(i, i + 1, "&#39");
                    break;
                case JPAKEParticipant.STATE_ROUND_2_VALIDATED:
                    buf.replace(i, i + 1, "&#40");
                    break;
                case ')':
                    buf.replace(i, i + 1, "&#41");
                    break;
                case '+':
                    buf.replace(i, i + 1, "&#43");
                    break;
                case '-':
                    buf.replace(i, i + 1, "&#45");
                    break;
                case ';':
                    buf.replace(i, i + 1, "&#59");
                    break;
                case JPAKEParticipant.STATE_ROUND_3_CREATED:
                    buf.replace(i, i + 1, "&#60");
                    break;
                case '>':
                    buf.replace(i, i + 1, "&#62");
                    break;
            }
            i += 4;
        }
        return buf.toString();
    }

    @Override // com.mi.car.jsse.easysec.i18n.filter.Filter
    public String doFilterUrl(String input) {
        return doFilter(input);
    }
}
