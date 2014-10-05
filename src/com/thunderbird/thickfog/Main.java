package com.thunderbird.thickfog;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Security;

/*
TODO - increase bcrypt factor to 8
TODO - generate salt from picture
*/

public class Main {
  final private static Logger LOGGER = LoggerFactory.getLogger(Main.class);
  final static byte[] key0 = new byte[Crypto.BLOCK_SIZE * 2];
  final static byte[] key1 = new byte[Crypto.BLOCK_SIZE * 2];
  final static byte[] IV = new byte[Crypto.BLOCK_SIZE];

  public static void main(String[] args) {
    // -- Security initialisations
    Utils.removeCryptographyRestrictions();
    Security.addProvider(new BouncyCastleProvider());

    // -- Generate secure password (Serpent + AES + basic IV)
    byte[] bt = SCrypt.generate("5at15fact10n".getBytes(), "salt&p=55a".getBytes(), 65536, 8, 1, Crypto.BLOCK_SIZE * 5);
    System.arraycopy(bt, 0, key0, 0, key0.length);
    System.arraycopy(bt, Crypto.BLOCK_SIZE * 2, key1, 0, key1.length);
    System.arraycopy(bt, Crypto.BLOCK_SIZE * 4, IV, 0, IV.length);
    // TODO remove: split secure password
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Secure pass: " + Integer.toString(bt.length));
      LOGGER.debug(Utils.bytesToHex(bt));
      LOGGER.debug("Key 0: " + Integer.toString(key0.length));
      LOGGER.debug(Utils.bytesToHex(key0));
      LOGGER.debug("Key 1: " + Integer.toString(key1.length));
      LOGGER.debug(Utils.bytesToHex(key1));
      LOGGER.debug("IV: " + Integer.toString(IV.length));
      LOGGER.debug(Utils.bytesToHex(IV));
    }

    Pipe p = new Pipe("C:/TD/gibberish.txt", "C:/TD/ENC", key0, key1, IV);
    p.push();
    // p.pull();
  }
}
