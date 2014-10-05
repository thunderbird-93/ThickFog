package com.thunderbird.thickfog;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;

@XmlRootElement
@XmlType(propOrder = {"name", "size", "lastModified", "checkSum", "IV0", "IV1", "chunks"})
public class FileManifest {
  private String name;
  private long size;
  private long lastModified;
  private byte[] checkSum = new byte[Crypto.BLOCK_SIZE * 4];    // SHA-512
  private byte[] IV0 = new byte[Crypto.BLOCK_SIZE];
  private byte[] IV1 = new byte[Crypto.BLOCK_SIZE];
  private ArrayList<ChunkManifest> chunks;

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

  @XmlAttribute
  public long getLastModified() {
    return lastModified;
  }

  public void setLastModified(long lastModified) {
    this.lastModified = lastModified;
  }

  public byte[] getCheckSum() {
    return checkSum;
  }

  public void setCheckSum(byte[] checkSum) {
    this.checkSum = checkSum;
  }

  public byte[] getIV0() {
    return IV0;
  }

  public void setIV0(byte[] IV0) {
    this.IV0 = IV0;
  }

  public byte[] getIV1() {
    return IV1;
  }

  public void setIV1(byte[] IV1) {
    this.IV1 = IV1;
  }

  @XmlElementWrapper(name = "fileChunks")
  @XmlElement(name = "chunk")
  public ArrayList<ChunkManifest> getChunks() {
    return chunks;
  }

  public void setChunks(ArrayList<ChunkManifest> chunks) {
    this.chunks = chunks;
  }
}
