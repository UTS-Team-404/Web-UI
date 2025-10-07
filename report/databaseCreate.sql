-- Project table
CREATE TABLE IF NOT EXISTS ProjectDB (
  ID INT AUTO_INCREMENT PRIMARY KEY,
  startTime DATETIME NOT NULL,
  stopTime DATETIME NULL,
  projectType VARCHAR(32) NULL
);

-- Packet/measurement table
CREATE TABLE IF NOT EXISTS IngestDB (
  ID INT AUTO_INCREMENT PRIMARY KEY,
  projectID INT NOT NULL,
  captureTime DATETIME NOT NULL,
  srcMac VARCHAR(17) NOT NULL,
  dstMac VARCHAR(17) NULL,
  SSID VARCHAR(64) NULL,
  encType VARCHAR(32) NULL,
  authMode VARCHAR(32) NULL,
  gpsLat INT NULL,
  gpsLong INT NULL,
  strength INT NULL,
  contentLength INT NULL,
  typeExternal VARCHAR(32) NULL,
  typeInternal VARCHAR(32) NULL,
  srcIP VARCHAR(45) NULL,
  dstIP VARCHAR(45) NULL,
  srcPort INT NULL,
  dstPort INT NULL,
  sniffType VARCHAR(16) NULL,
  CONSTRAINT fk_project FOREIGN KEY (projectID) REFERENCES ProjectDB(ID)
);
