package com.thunderbird.thickfog;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

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
    BufferedInputStream bis;
    BufferedOutputStream bos;
    byte[] buf;                                   // main buffer pointer
    byte[] standardBuf;
    byte[] lastChunkBuf;
    final Integer CHUNK_SIZE = 1024 * 1024 * 4;  // 4MB chunks
    int br;
    int i;
    FileInputStream fis;
    FileOutputStream fos;

    Utils.removeCryptographyRestrictions();
    Security.addProvider(new BouncyCastleProvider());


    // -- Generate secure password (Serpent + AES + basic IV)
    byte[] bt = SCrypt.generate("5at15fact10n".getBytes(), "salt&p=ppa".getBytes(), 65536, 8, 1, Crypto.BLOCK_SIZE * 5);
    System.arraycopy(bt, 0, key0, 0, key0.length);
    System.arraycopy(bt, Crypto.BLOCK_SIZE * 2, key1, 0, key1.length);
    System.arraycopy(bt, Crypto.BLOCK_SIZE * 4, IV, 0, IV.length);
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

    Pipe p = new Pipe("C:/TD/gibberish.txt", "C:/TD/", key0, key1, IV);
    p.push();

    if (true) return;

    // -- Crypt String / Base62 example
    Crypto_AES_CBC c = new Crypto_AES_CBC(key0, IV);
    try {
      c.initCiphers();
      String s = c.encrypt("Hello you lazy bastards Base62");
      if (LOGGER.isDebugEnabled()) LOGGER.debug(s);
      if (LOGGER.isDebugEnabled()) LOGGER.debug(c.decrypt(s));
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }

    // -- XML file example (JAXB)
    try {
      final String FILE_MANIFEST_XML = "c:/TD/test.zip.manifest";

      ArrayList<ChunkManifest> chunks = new ArrayList<ChunkManifest>();

      ChunkManifest cm1 = new ChunkManifest();
      cm1.setName("test.zip.part0");
      cm1.setSize(89888743);
      cm1.setCheckSum("s+mple1t34)6012$45678=01234a67z*".getBytes());
      cm1.setEncCheckSum("s0mpSe1t34)6012$45678=01234a67z-".getBytes());
      chunks.add(cm1);

      ChunkManifest cm2 = new ChunkManifest();
      cm2.setName("test.zip.part1");
      cm2.setSize(34888);
      cm2.setCheckSum("s+mple1t34)6012$45678=01234a67z*".getBytes());
      cm2.setEncCheckSum("s0mpSe1t34)6012$45678=01234a67z-".getBytes());
      chunks.add(cm2);

      FileManifest fm = new FileManifest();
      fm.setName("test.zip");
      fm.setSize(89888743 + 34888);
      fm.setCheckSum("s+mple1t34)6012wr3j78=01234a67z*".getBytes());
      fm.setIV0("IV0_le1234560123".getBytes());
      fm.setIV1("IV1_le1234560123".getBytes());
      fm.setChunks(chunks);

      // create JAXB context and instantiate marshaller
      JAXBContext context = JAXBContext.newInstance(FileManifest.class);
      Marshaller m = context.createMarshaller();
      m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

      // Write to System.out
      m.marshal(fm, System.out);

      // Write to File
      m.marshal(fm, new File(FILE_MANIFEST_XML));

      // get variables from our xml file, created before
      System.out.println();
      System.out.println("Output from our XML File: ");

      Unmarshaller um = context.createUnmarshaller();
      FileManifest fm2 = (FileManifest) um.unmarshal(new FileReader(FILE_MANIFEST_XML));
      ArrayList<ChunkManifest> list = fm2.getChunks();
      for (ChunkManifest cm : list) {
        System.out.println("Chunk: " + cm.getName() + " size: "
            + cm.getSize());
      }
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }


    if (true) return;

    // -- CBC Encrypt
    Crypto_Serpent_AES_CBC c1 = new Crypto_Serpent_AES_CBC("sample1234)6012$45678=01234567z*".getBytes(),
        "sample1234560123".getBytes(), "sample12345601234567890123456789".getBytes(),
        "sample1234560123".getBytes());

    // -- Encrypt file
    try {
      c1.initCiphers();
      fis = new FileInputStream("C:/TD/gbr_in.txt");
      fos = new FileOutputStream("C:/TD/gbr_out.txt");
      c1.encrypt(fis, fos);
      fis.close();
      fos.close();
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }

   // ECB Encrypt
    try {
      c1.initCiphers();
      fis = new FileInputStream("C:/TD/gbr_in.txt");
      fos = new FileOutputStream("C:/TD/gbr_out.txt");
      c1.encrypt(fis, fos);
      fis.close();
      fos.close();
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }

    // ECB decrypt
    try {
      c.initCiphers();
      fis = new FileInputStream("C:/TD/gbr_out.txt");
      fos = new FileOutputStream("C:/TD/gbr.txt");
      c.decrypt(fis, fos);
      fis.close();
      fos.close();
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }


    try {
      // -- Open file
      bis = new BufferedInputStream(new FileInputStream("C:/TD/gibberish.txt"));
      if (LOGGER.isDebugEnabled()) LOGGER.debug("Size: " + bis.available() / (1024 * 1024));

      // -- Read and write chunks
      standardBuf = new byte[CHUNK_SIZE];
      i = 0;
      MessageDigest md = MessageDigest.getInstance("SHA-512");
      while (bis.available() > 0) {
        // read byte into buf , starts at offset 2, 3 bytes to read
        if (bis.available() >= CHUNK_SIZE) {
          br = bis.read(standardBuf, 0, CHUNK_SIZE);
          buf = standardBuf;
        }
        else {
          lastChunkBuf = new byte[bis.available()];
          br = bis.read(lastChunkBuf, 0, bis.available());
          buf = lastChunkBuf;
        }

        // -- Hashing
        md.reset();
        md.update(buf);
        byte[] mdbytes = md.digest();
        // for (int k = 0; k < mdbytes.length; k++) {
        //  System.out.print(Integer.toHexString(0xFF & mdbytes[k]));
        // }
        if (LOGGER.isDebugEnabled()) LOGGER.debug(Utils.bytesToHex(mdbytes));

        // -- Diagnostics
        if (LOGGER.isDebugEnabled()) LOGGER.debug("Read: " + br);
        if (br < CHUNK_SIZE) {
          if (LOGGER.isDebugEnabled()) LOGGER.debug("Last-------");
        }
        if (LOGGER.isDebugEnabled()) LOGGER.debug("Remaining: " + bis.available());

        // -- Write separate files
        bos = new BufferedOutputStream(new FileOutputStream("C:/TD/gibberish.part" + i));
        bos.write(buf);
        bos.close();
        i++;
      }
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }
    finally {
      if (bis != null) {
        try {
          bis.close();
        } catch (Exception e) {
          if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
        }
      }
    }
  }
}

