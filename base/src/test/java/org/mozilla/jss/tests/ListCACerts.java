package org.mozilla.jss.tests;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Cert;

public class ListCACerts {
    public static void main(String args[]) throws Exception {
        if (args.length > 2) {
            System.out.println(
                "Usage: java org.mozilla.jss.tests.ListCACerts <dbdir> [verbose]");
            System.exit(1);
        }

        CryptoManager cm = CryptoManager.getInstance();

        X509Certificate[] certs = cm.getCACerts();
        System.out.println("Number of CA certs: " + certs.length);
        System.out.println("use option \"verbose\" if you want the CA " +
            "certs printed out");

        if (args.length == 2 && args[1].equalsIgnoreCase("verbose")) {
            for (int i = 0; i < certs.length; i++) {
                System.out.println(certs[i].getSubjectDN().toString());
                PK11Cert ic = (PK11Cert) certs[i];
                System.out.println("SSL: " + ic.getSSLTrust() +
                    ", Email: " + ic.getEmailTrust() +
                    ", Object Signing: " + ic.getObjectSigningTrust());
            }
        }
    }
}
