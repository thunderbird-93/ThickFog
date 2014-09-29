package com.thunderbird.thickfog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.PropertyException;
import java.io.*;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;

public class Pipe {
  final private static Logger LOGGER = LoggerFactory.getLogger(Pipe.class);
  final public static int CHUNK_SIZE = 4194304;     // 4MB chunk size
  final static String MANIFEST_EXT = ".manifest";
  final static String CHUNK_EXT = ".part";

  private Crypto_AES_CBC lightCipher;
  private Crypto_Serpent_AES_CBC heavyChipher;
  private File originalFile;                         // Original file path & name
  private File encryptedPath;                        // Folder where file Manifest and Chunks are stored
  private FileManifest manifest;

/*  - private FileManifest
  - private HashingDigest
  - update()
  - push()
  - pull()
  - private readManifest
*/

  public Pipe(String originalFile, String encryptedPath, byte[] key0, byte[] key1, byte[] IV) {
    this.originalFile = new File(originalFile);
    this.encryptedPath = new File(encryptedPath);

    // -- create manifest instance and generate initialization vectors
    manifest = new FileManifest();
    manifest.setIV0(Utils.getSecureRandom(Crypto.BLOCK_SIZE));
    manifest.setIV1(Utils.getSecureRandom(Crypto.BLOCK_SIZE));
    manifest.setName(this.originalFile.getName());
    manifest.setSize(this.originalFile.length());
    manifest.setChunks(new ArrayList<ChunkManifest>());

    try {
      lightCipher = new Crypto_AES_CBC(key0, IV);
      lightCipher.initCiphers();
      heavyChipher = new Crypto_Serpent_AES_CBC(key0, manifest.getIV0(), key1, manifest.getIV1());
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }
  }

  // -- Split original file into chunks, encrypt them and create manifest file
  public void push() {
    BufferedInputStream bis = null;
    int bytesRead;

    try {
      // -- Open original file
      bis = new BufferedInputStream(new FileInputStream(originalFile));
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Opening: " + originalFile);
        LOGGER.debug("Size: " + originalFile.length() / (1024 * 1024) + "MB");
      }

      // -- Split file into chunks, calculate hashes & update manifest accordingly
      manifest.setIV0(heavyChipher.getIV0());
      manifest.setIV1(heavyChipher.getIV());

      byte[] originalBuf = new byte[CHUNK_SIZE];        // original data chunk buffer
      byte[] encryptedBuf = new byte[CHUNK_SIZE];       // encrypted data chunk buffer
      int i = 0;
      MessageDigest originalFileDigest = MessageDigest.getInstance("SHA-512", "BC");
      originalFileDigest.reset();
      MessageDigest chunkDigest = MessageDigest.getInstance("SHA-512", "BC");
      while (bis.available() > 0) {
        // read chunk
        if (bis.available() >= CHUNK_SIZE) {
          bytesRead = bis.read(originalBuf, 0, CHUNK_SIZE);
        } else {
          originalBuf = new byte[bis.available()];
          bytesRead = bis.read(originalBuf, 0, bis.available());
        }

        // checksums
        originalFileDigest.update(originalBuf);
        chunkDigest.reset();
        chunkDigest.update(originalBuf);
        ChunkManifest cm = new ChunkManifest();
        cm.setCheckSum(chunkDigest.digest());
        cm.setName(originalFile.getName() + CHUNK_EXT + i);
        cm.setSize(bytesRead);

        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("cm" + i + " " + cm.getName());
          LOGGER.debug("cm" + i + " " + cm.getSize() / 1024);                   // KB
          LOGGER.debug("cm" + i + " " + Utils.bytesToHex(cm.getCheckSum()));
        }

        manifest.getChunks().add(cm);

        i++;
      }

      // whole original file checksum
      manifest.setCheckSum(originalFileDigest.digest());
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(originalFile.getName() + " checksum");
        LOGGER.debug(Utils.bytesToHex(manifest.getCheckSum()));
      }

      writeManifest();
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }
    finally {
      try {
        if (bis != null) bis.close();
      } catch (Exception e) {
        if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
      }
    }
  }

  private void writeManifest() {
    FileOutputStream fos = null;

    // -- Write Manifest file through JAXB
    try {
      JAXBContext jc = JAXBContext.newInstance(FileManifest.class);
      Marshaller m = jc.createMarshaller();
      m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
      // TODO remove: Create unencrypted file only in DEBUG mode; TODO
      if (LOGGER.isDebugEnabled()) {
        m.marshal(manifest, new File(originalFile + MANIFEST_EXT + ".plain"));
      }
      // Buffer JAXB XML output
      ByteArrayOutputStream ba_out = new ByteArrayOutputStream();
      m.marshal(manifest, ba_out);
      ByteArrayInputStream ba_in = new ByteArrayInputStream(ba_out.toByteArray());
      // Encrypt manifest file name
      fos = new FileOutputStream(new File(originalFile.getParent()
          + originalFile.separator + lightCipher.encrypt(originalFile.getName() + MANIFEST_EXT)));
      // Encrypt manifest content
      lightCipher.encrypt(ba_in, fos);
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }
    finally {
      try {
        if (fos != null) fos.close();
      } catch (Exception e) {
        if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
      }
    }
  }

  public File getOriginalFile() {
    return originalFile;
  }

  public void setOriginalFile(File originalFile) {
    this.originalFile = originalFile;
  }

  public File getEncryptedPath() {
    return encryptedPath;
  }

  public void setEncryptedPath(File encryptedPath) {
    this.encryptedPath = encryptedPath;
  }
}
