/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class PK11ECPublicKey
    extends PK11PubKey
    implements ECPublicKey {

    public static Logger logger = LoggerFactory.getLogger(PK11ECPublicKey.class);

    private static final long serialVersionUID = 1L;
    public PK11ECPublicKey(byte[] pointer) {
        super(pointer);
    }

//
// Requires JAVA 1.5
//    public ECParams getCurve() {
//      try {
//        return new BigInteger( getCurveByteArray() );
//      } catch(NumberFormatException e) {
//          throw new RuntimeException("Unable to decode DSA parameters: " + e.getMessage(), e);
//      }
//    }
//

    public BigInteger getCurve() {
      try {
        return new BigInteger( getCurveByteArray() );
      } catch(NumberFormatException e) {
          throw new RuntimeException("Unable to decode EC curve: " + e.getMessage(), e);
      }
    }

    public byte[] getCurveBA() {
        return getCurveByteArray();
    }

    public ECPoint getW() {
        logger.debug("PK11ECPublicKey: getW()", new Exception());
        BigInteger w = new BigInteger( getWByteArray() );
        return null;
    }

    private native byte[] getCurveByteArray();
    public native byte[] getWByteArray();

    @Override
    public ECParameterSpec getParams() {
        logger.debug("PK11ECPublicKey: getParams()", new Exception());
        return null;
    }
}
