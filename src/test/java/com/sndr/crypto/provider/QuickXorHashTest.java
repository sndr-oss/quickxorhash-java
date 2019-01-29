package com.sndr.crypto.provider;

import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;

/**
 * The QuickXorHash Provider implementation for testing purposes.
 */
public class QuickXorHashTest {

    private static final String HASH_ALGORITHM = "QuickXorHash";
    private static final Map<String, String> TEST_VECTORS = createMap();

    /**
     * Test Vectors from the rclone client
     *
     * @see
     * https://raw.githubusercontent.com/ncw/rclone/f0e1158215519b13698a9ad4026196592803c593/backend/onedrive/quickxorhash/quickxorhash_test.go
     * @return
     */
    private static Map<String, String> createMap() {
        Map<String, String> map = new HashMap<>();
        map.put("", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        map.put("Sg==", "SgAAAAAAAAAAAAAAAQAAAAAAAAA=");
        map.put("tbQ=", "taAFAAAAAAAAAAAAAgAAAAAAAAA=");
        map.put("0pZP", "0rDEEwAAAAAAAAAAAwAAAAAAAAA=");
        map.put("jRRDVA==", "jaDAEKgAAAAAAAAABAAAAAAAAAA=");
        map.put("eAV52qE=", "eChAHrQRCgAAAAAABQAAAAAAAAA=");
        map.put("luBZlaT6", "lgBHFipBCn0AAAAABgAAAAAAAAA=");
        map.put("qaApEj66lw==", "qQBFCiTgA11cAgAABwAAAAAAAAA=");
        map.put("/aNzzCFPS/A=", "/RjFHJgRgicsAR4ACAAAAAAAAAA=");
        map.put("n6Neh7p6fFgm", "nxiFFw6hCz3wAQsmCQAAAAAAAAA=");
        map.put("J9iPGCbfZSTNyw==", "J8DGIzBggm+UgQTNUgYAAAAAAAA=");
        map.put("i+UZyUGJKh+ISbk=", "iyhHBpIRhESo4AOIQ0IuAAAAAAA=");
        map.put("h490d57Pqz5q2rtT", "h3gEHe7giWeswgdq3MYupgAAAAA=");
        map.put("vPgoDjOfO6fm71RxLw==", "vMAHChwwg0/s4BTmdQcV4vACAAA=");
        map.put("XoJ1AsoR4fDYJrDqYs4=", "XhBEHQSgjAiEAx7YPgEs1CEGZwA=");
        map.put("gQaybEqS/4UlDc8e4IJm", "gDCALNigBEn8oxAlZ8AzPAAOQZg=");
        map.put("2fuxhBJXtpWFe8dOfdGeHw==", "O9tHLAghgSvYohKFyMMxnNCHaHg=");
        map.put("XBV6YKU9V7yMakZnFIxIkuU=", "HbplHsBQih5cgReMQYMRzkABRiA=");
        map.put("XJZSOiNO2bmfKnTKD7fztcQX", "/6ZArHQwAidkIxefQgEdlPGAW8w=");
        map.put("g8VtAh+2Kf4k0kY5tzji2i2zmA==", "wDNrgwHWAVukwB8kg4YRcnALHIg=");
        map.put("T6LYJIfDh81JrAK309H2JMJTXis=", "zBTHrspn3mEcohlJdIUAbjGNaNg=");
        map.put("DWAAX5/CIfrmErgZa8ot6ZraeSbu", "LR2Z0PjuRYGKQB/mhQAuMrAGZbQ=");
        map.put("N9abi3qy/mC1THZuVLHPpx7SgwtLOA==", "1KTYttCBEen8Hwy1doId3ECFWDw=");
        map.put("LlUe7wHerLqEtbSZLZgZa9u0m7hbiFs=", "TqVZpxs3cN61BnuFvwUtMtECTGQ=");
        map.put("bU2j/0XYdgfPFD4691jV0AOUEUPR4Z5E", "bnLBiLpVgnxVkXhNsIAPdHAPLFQ=");
        map.put("lScPwPsyUsH2T1Qsr31wXtP55Wqbe47Uyg==", "VDMSy8eI26nBHCB0e8gVWPCKPsA=");
        map.put("rJaKh1dLR1k+4hynliTZMGf8Nd4qKKoZiAM=", "r7bjwkl8OYQeNaMcCY8fTmEJEmQ=");
        map.put("pPsT0CPmHrd3Frsnva1pB/z1ytARLeHEYRCo", "Rdg7rCcDomL59pL0s6GuTvqLVqQ=");
        map.put("wSRChaqmrsnMrfB2yqI43eRWbro+f9kBvh+01w==", "YTtloIi6frI7HX3vdLvE7I2iUOA=");
        map.put("apL67KMIRxQeE9k1/RuW09ppPjbF1WeQpTjSWtI=", "CIpedls+ZlSQ654fl+X26+Q7LVU=");
        map.put("53yx0/QgMTVb7OOzHRHbkS7ghyRc+sIXxi7XHKgT", "zfJtLGFgR9DB3Q64fAFIp+S5iOY=");
        map.put("PwXNnutoLLmxD8TTog52k8cQkukmT87TTnDipKLHQw==", "PTaGs7yV3FUyBy/SfU6xJRlCJlI=");
        map.put("NbYXsp5/K6mR+NmHwExjvWeWDJFnXTKWVlzYHoesp2E=", "wjuAuWDiq04qDt1R8hHWDDcwVoQ=");
        map.put("qQ70RB++JAR5ljNv3lJt1PpqETPsckopfonItu18Cr3E", "FkJaeg/0Z5+euShYlLpE2tJh+Lo=");
        map.put("RhzSatQTQ9/RFvpHyQa1WLdkr3nIk6MjJUma998YRtp44A==", "SPN2D29reImAqJezlqV2DLbi8tk=");
        map.put("DND1u1uZ5SqZVpRUk6NxSUdVo7IjjL9zs4A1evDNCDLcXWc=", "S6lBk2hxI2SWBfn7nbEl7D19UUs=");
        map.put("jEi62utFz69JMYHjg1iXy7oO6ZpZSLcVd2B+pjm6BGsv/CWi", "s0lYU9tr/bp9xsnrrjYgRS5EvV8=");
        map.put("hfS3DZZnhy0hv7nJdXLv/oJOtIgAuP9SInt/v8KeuO4/IvVh4A==", "CV+HQCdd2A/e/vdi12f2UU55GLA=");
        map.put("EkPQAC6ymuRrYjIXD/LT/4Vb+7aTjYVZOHzC8GPCEtYDP0+T3Nc=", "kE9H9sEmr3vHBYUiPbvsrcDgSEo=");
        map.put("vtBOGIENG7yQ/N7xNWPNIgy66Gk/I2Ur/ZhdFNUK9/1FCZuu/KeS", "+Fgp3HBimtCzUAyiinj3pkarYTk=");
        map.put("YnF4smoy9hox2jBlJ3VUa4qyCRhOZbWcmFGIiszTT4zAdYHsqJazyg==", "arkIn+ELddmE8N34J9ydyFKW+9w=");
        map.put("0n7nl3YJtipy6yeUbVPWtc2h45WbF9u8hTz5tNwj3dZZwfXWkk+GN3g=", "YJLNK7JR64j9aODWfqDvEe/u6NU=");
        map.put("FnIIPHayc1pHkY4Lh8+zhWwG8xk6Knk/D3cZU1/fOUmRAoJ6CeztvMOL", "22RPOylMtdk7xO/QEQiMli4ql0k=");
        map.put("J82VT7ND0Eg1MorSfJMUhn+qocF7PsUpdQAMrDiHJ2JcPZAHZ2nyuwjoKg==", "pOR5eYfwCLRJbJsidpc1rIJYwtM=");
        map.put("Zbu+78+e35ZIymV5KTDdub5McyI3FEO8fDxs62uWHQ9U3Oh3ZqgaZ30SnmQ=", "DbvbTkgNTgWRqRidA9r1jhtUjro=");
        map.put("lgybK3Da7LEeY5aeeNrqcdHvv6mD1W4cuQ3/rUj2C/CNcSI0cAMw6vtpVY3y", "700RQByn1lRQSSme9npQB/Ye+bY=");
        map.put("jStZgKHv4QyJLvF2bYbIUZi/FscHALfKHAssTXkrV1byVR9eACwW9DNZQRHQwg==", "uwN55He8xgE4g93dH9163xPew4U=");
        map.put("V1PSud3giF5WW72JB/bgtltsWtEB5V+a+wUALOJOGuqztzVXUZYrvoP3XV++gM0=", "U+3ZfUF/6mwOoHJcSHkQkckfTDA=");
        map.put("VXs4t4tfXGiWAL6dlhEMm0YQF0f2w9rzX0CvIVeuW56o6/ec2auMpKeU2VeteEK5", "sq24lSf7wXLH8eigHl07X+qPTps=");
        map.put("bLUn3jLH+HFUsG3ptWTHgNvtr3eEv9lfKBf0jm6uhpqhRwtbEQ7Ovj/hYQf42zfdtQ==", "uC8xrnopGiHebGuwgq607WRQyxQ=");
        map.put("4SVmjtXIL8BB8SfkbR5Cpaljm2jpyUfAhIBf65XmKxHlz9dy5XixgiE/q1lv+esZW/E=", "wxZ0rxkMQEnRNAp8ZgEZLT4RdLM=");
        map.put("pMljctlXeFUqbG3BppyiNbojQO3ygg6nZPeUZaQcVyJ+Clgiw3Q8ntLe8+02ZSfyCc39", "aZEPmNvOXnTt7z7wt+ewV7QGMlg=");
        map.put("C16uQlxsHxMWnV2gJhFPuJ2/guZ4N1YgmNvAwL1yrouGQtwieGx8WvZsmYRnX72JnbVtTw==", "QtlSNqXhVij64MMhKJ3EsDFB/z8=");
        map.put("7ZVDOywvrl3L0GyKjjcNg2CcTI81n2CeUbzdYWcZOSCEnA/xrNHpiK01HOcGh3BbxuS4S6g=", "4NznNJc4nmXeApfiCFTq/H5LbHw=");
        map.put("JXm2tTVqpYuuz2Cc+ZnPusUb8vccPGrzWK2oVwLLl/FjpFoxO9FxGlhnB08iu8Q/XQSdzHn+", "IwE5+2pKNcK366I2k2BzZYPibSI=");
        map.put("TiiU1mxzYBSGZuE+TX0l9USWBilQ7dEml5lLrzNPh75xmhjIK8SGqVAkvIMgAmcMB+raXdMPZg==", "yECGHtgR128ScP4XlvF96eLbIBE=");
        map.put("zz+Q4zi6wh0fCJUFU9yUOqEVxlIA93gybXHOtXIPwQQ44pW4fyh6BRgc1bOneRuSWp85hwlTJl8=", "+3Ef4D6yuoC8J+rbFqU1cegverE=");
        map.put("sa6SHK9z/G505bysK5KgRO2z2cTksDkLoFc7sv0tWBmf2G2mCiozf2Ce6EIO+W1fRsrrtn/eeOAV", "xZg1CwMNAjN0AIXw2yh4+1N3oos=");
        map.put("0qx0xdyTHhnKJ22IeTlAjRpWw6y2sOOWFP75XJ7cleGJQiV2kyrmQOST4DGHIL0qqA7sMOdzKyTViw==", "bS0tRYPkP1Gfc+ZsBm9PMzPunG8=");
        map.put("QuzaF0+5ooig6OLEWeibZUENl8EaiXAQvK9UjBEauMeuFFDCtNcGs25BDtJGGbX90gH4VZvCCDNCq4s=", "rggokuJq1OGNOfB6aDp2g4rdPgw=");
        map.put("+wg2x23GZQmMLkdv9MeAdettIWDmyK6Wr+ba23XD+Pvvq1lIMn9QIQT4Z7QHJE3iC/ZMFgaId9VAyY3d", "ahQbTmOdiKUNdhYRHgv5/Ky+Y6k=");
        map.put("y0ydRgreRQwP95vpNP92ioI+7wFiyldHRbr1SfoPNdbKGFA0lBREaBEGNhf9yixmfE+Azo2AuROxb7Yc7g==", "cJKFc0dXfiN4hMg1lcMf5E4gqvo=");
        map.put("LxlVvGXSQlSubK8r0pGf9zf7s/3RHe75a2WlSXQf3gZFR/BtRnR7fCIcaG//CbGfodBFp06DBx/S9hUV8Bk=", "NwuwhhRWX8QZ/vhWKWgQ1+rNomI=");
        map.put("L+LSB8kmGMnHaWVA5P/+qFnfQliXvgJW7d2JGAgT6+koi5NQujFW1bwQVoXrBVyob/gBxGizUoJMgid5gGNo", "ndX/KZBtFoeO3xKeo1ajO/Jy+rY=");
        map.put("Mb7EGva2rEE5fENDL85P+BsapHEEjv2/siVhKjvAQe02feExVOQSkfmuYzU/kTF1MaKjPmKF/w+cbvwfdWL8aQ==", "n1anP5NfvD4XDYWIeRPW3ZkPv1Y=");
        map.put("jyibxJSzO6ZiZ0O1qe3tG/bvIAYssvukh9suIT5wEy1JBINVgPiqdsTW0cOpP0aUfP7mgqLfADkzI/m/GgCuVhr8oFLrOCoTx1/psBOWwhltCbhUx51Icm9aH8tY4Z3ccU+6BKpYQkLCy0B/A9Zc", "hZfLIilSITC6N3e3tQ/iSgEzkto=");
        map.put("ikwCorI7PKWz17EI50jZCGbV9JU2E8bXVfxNMg5zdmqSZ2NlsQPp0kqYIPjzwTg1MBtfWPg53k0h0P2naJNEVgrqpoHTfV2b3pJ4m0zYPTJmUX4Bg/lOxcnCxAYKU29Y5F0U8Quz7ZXFBEweftXxJ7RS4r6N7BzJrPsLhY7hgck=", "imAoFvCWlDn4yVw3/oq1PDbbm6U=");
        map.put("PfxMcUd0vIW6VbHG/uj/Y0W6qEoKmyBD0nYebEKazKaKG+UaDqBEcmQjbfQeVnVLuodMoPp7P7TR1htX5n2VnkHh22xDyoJ8C/ZQKiSNqQfXvh83judf4RVr9exJCud8Uvgip6aVZTaPrJHVjQhMCp/dEnGvqg0oN5OVkM2qqAXvA0teKUDhgNM71sDBVBCGXxNOR2bpbD1iM4dnuT0ey4L+loXEHTL0fqMeUcEi2asgImnlNakwenDzz0x57aBwyq3AspCFGB1ncX4yYCr/OaCcS5OKi/00WH+wNQU3", "QX/YEpG0gDsmhEpCdWhsxDzsfVE=");
        map.put("qwGf2ESubE5jOUHHyc94ORczFYYbc2OmEzo+hBIyzJiNwAzC8PvJqtTzwkWkSslgHFGWQZR2BV5+uYTrYT7HVwRM40vqfj0dBgeDENyTenIOL1LHkjtDKoXEnQ0mXAHoJ8PjbNC93zi5TovVRXTNzfGEs5dpWVqxUzb5lc7dwkyvOluBw482mQ4xrzYyIY1t+//OrNi1ObGXuUw2jBQOFfJVj2Y6BOyYmfB1y36eBxi3zxeG5d5NYjm2GSh6e08QMAwu3zrINcqIzLOuNIiGXBtl7DjKt7b5wqi4oFiRpZsCyx2smhSrdrtK/CkdU6nDN+34vSR/M8rZpWQdBE7a8g==", "WYT9JY3JIo/pEBp+tIM6Gt2nyTM=");
        map.put("w0LGhqU1WXFbdavqDE4kAjEzWLGGzmTNikzqnsiXHx2KRReKVTxkv27u3UcEz9+lbMvYl4xFf2Z4aE1xRBBNd1Ke5C0zToSaYw5o4B/7X99nKK2/XaUX1byLow2aju2XJl2OpKpJg+tSJ2fmjIJTkfuYUz574dFX6/VXxSxwGH/xQEAKS5TCsBK3CwnuG1p5SAsQq3gGVozDWyjEBcWDMdy8/AIFrj/y03Lfc/RNRCQTAfZbnf2QwV7sluw4fH3XJr07UoD0YqN+7XZzidtrwqMY26fpLZnyZjnBEt1FAZWO7RnKG5asg8xRk9YaDdedXdQSJAOy6bWEWlABj+tVAigBxavaluUH8LOj+yfCFldJjNLdi90fVHkUD/m4Mr5OtmupNMXPwuG3EQlqWUVpQoYpUYKLsk7a5Mvg6UFkiH596y5IbJEVCI1Kb3D1", "e3+wo77iKcILiZegnzyUNcjCdoQ=");
        return map;
    }

    @BeforeClass
    public static void setUpBeforeClass() {
        Security.addProvider(new QuickXorHashProvider());
    }

    @Test
    public final void digest_ValidUpdateWithBytes_Successful() throws NoSuchAlgorithmException {
        final String input = "quick_xor_hash_text_of_some_sort";
        final byte[] expected = Base64.getDecoder().decode("x26n1MWtON/m0nET1m1ygSm5BPs=");

        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        MessageDigest digester = MessageDigest.getInstance(HASH_ALGORITHM);
        digester.update(inputBytes);
        byte[] actual = digester.digest();

        assertArrayEquals("Hashed value does not match expected value.", expected, actual);
    }

    @Test
    public final void digest_Rclone_Values_ValidUpdateWithBytes_Successful() throws NoSuchAlgorithmException {
        for (Map.Entry<String, String> testVector : TEST_VECTORS.entrySet()) {

            final byte[] inputBytes = Base64.getDecoder().decode(testVector.getKey());
            final byte[] expected = Base64.getDecoder().decode(testVector.getValue());
            
            MessageDigest digester = MessageDigest.getInstance(HASH_ALGORITHM);
            digester.update(inputBytes);
            byte[] actual = digester.digest();
                                
            assertArrayEquals("Hashed value does not match expected value.", expected, actual);

        }
    }
}
