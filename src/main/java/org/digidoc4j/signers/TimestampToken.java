package org.digidoc4j.signers;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.Configuration;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.SkDataLoader;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;

/**
 * Timestamp token for AsicS container
 * <p>
 * Created by Andrei on 7.12.2017.
 */
public final class TimestampToken {
  private static final Logger logger = LoggerFactory.getLogger(TimestampToken.class);
  private TimestampToken() {
  }

  /**
   * generates timesstamp token for AsicS container
   *
   * @param digestAlgorithm
   * @param dataFiles
   * @return DataFile timestamp token
   */
  public static DataFile generateTimestampToken(DigestAlgorithm digestAlgorithm,
                                                List<ContainerBuilder.ContainerDataFile> dataFiles,
                                                Configuration configuration) {
    if (dataFiles.isEmpty()) {
      throw new DigiDoc4JException("Add data file first");
    }
    if (dataFiles.size() > 1) {
      throw new DigiDoc4JException("Supports only asics with only one datafile");
    }
    ContainerBuilder.ContainerDataFile containerDataFile = dataFiles.get(0);
    OnlineTSPSource onlineTSPSource = defineOnlineTSPSource(configuration);
    byte[] dataFileDigest = getDigest(containerDataFile);
    byte[] digest = DSSUtils.digest(digestAlgorithm, dataFileDigest);
    DataFile timeStampToken = getTimestampToken(onlineTSPSource, digestAlgorithm, digest);
    return timeStampToken;
  }

  /**
   * generates timesstamp token for AsicS container
   *
   * @param digestAlgorithm
   * @param containerDataFile
   * @return DataFile timestamp token
   */
  public static DataFile generateTimestampToken(DigestAlgorithm digestAlgorithm, DataFile containerDataFile) {
    OnlineTSPSource onlineTSPSource = defineOnlineTSPSource(null);
    byte[] dataFileDigest;
    dataFileDigest = containerDataFile.getBytes();
    byte[] digest = DSSUtils.digest(digestAlgorithm, dataFileDigest);
    DataFile timeStampToken = getTimestampToken(onlineTSPSource, digestAlgorithm, digest);
    return timeStampToken;
  }

  private static OnlineTSPSource defineOnlineTSPSource(Configuration configuration) {
    OnlineTSPSource source = new OnlineTSPSource();
    if (configuration == null) {
      configuration = Configuration.getInstance();
    }
    source.setTspServer(configuration.getTspSource());
    SkDataLoader loader = SkDataLoader.timestamp(configuration);
    loader.setUserAgent(Helper.createBDocAsicSUserAgent());
    source.setDataLoader(loader);
    return source;
  }

  private static DataFile getTimestampToken(OnlineTSPSource onlineTSPSource, DigestAlgorithm digestAlgorithm,
                                            byte[] digest) {
    DataFile timeStampToken = new DataFile();
    TimeStampToken timeStampResponse = onlineTSPSource.getTimeStampResponse(digestAlgorithm, digest);
    String timestampFilename = "timestamp";
    timeStampToken.setDocument(
        new InMemoryDocument(DSSASN1Utils.getEncoded(timeStampResponse), timestampFilename, MimeType.TST));
    timeStampToken.setMediaType(MimeType.TST.getMimeTypeString());
    return timeStampToken;
  }

  private static byte[] getDigest(ContainerBuilder.ContainerDataFile dataFile) {
    try {
      //byte[] dataFileDigest = new byte[0];
      logger.debug("isStream: " + dataFile.isStream);
      logger.debug("isByteArray: " + dataFile.isByteArray());
      logger.debug("isDataFile: " + dataFile.isDataFile());

      if(dataFile.isStream) {
        logger.debug("DATAFILE is inputStream...");
        byte[] dataFileDigest = IOUtils.toByteArray(dataFile.inputStream);
        logger.debug("DATAFILE data length: " + dataFileDigest.length);
        return dataFileDigest;
      } else if(dataFile.isByteArray()){
        logger.debug("DATAFILE is byte array...");
        byte[] dataFileDigest = dataFile.filedata;
        logger.debug("DATAFILE data length: " + dataFileDigest.length);
        return dataFileDigest;
      } else if(dataFile.isDataFile()){
        logger.debug("DATAFILE is DataFile...");
        byte[] dataFileDigest = dataFile.dataFile.getBytes();
        logger.debug("DATAFILE data length: " + dataFileDigest.length);
        return dataFileDigest;
      } else {
        logger.debug("DATAFILE is file... path: " + dataFile.filePath);
        Path path = Paths.get(dataFile.filePath);
        byte[] dataFileDigest = Files.readAllBytes(path);
        logger.debug("DATAFILE data length: " + dataFileDigest.length);
        return dataFileDigest;
      }

    } catch (IOException e) {
      e.printStackTrace();
    }
    throw new DigiDoc4JException("Cannot get file digest");
  }

}
