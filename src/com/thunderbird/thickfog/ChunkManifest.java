package com.thunderbird.thickfog;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class ChunkManifest {
  private String name;
  private long size;
  private byte[] checkSum = new byte[Crypto.BLOCK_SIZE * 4];      // SHA-512
  private byte[] encCheckSum = new byte[Crypto.BLOCK_SIZE * 4];   // SHA-512

  @XmlAttribute
  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  @XmlAttribute
  public long getSize() {
    return size;
  }

  public void setSize(long size) {
    this.size = size;
  }

  public byte[] getCheckSum() {
    return checkSum;
  }

  public void setCheckSum(byte[] checkSum) {
    this.checkSum = checkSum;
  }

  public byte[] getEncCheckSum() {
    return encCheckSum;
  }

  public void setEncCheckSum(byte[] encCheckSum) {
    this.encCheckSum = encCheckSum;
  }
}
