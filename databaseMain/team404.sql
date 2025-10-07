
CREATE DATABASE IF NOT EXISTS team404;

CREATE USER IF NOT EXISTS 'team404user'@'%' IDENTIFIED BY 'pass';

GRANT ALL PRIVILEGES ON team404.* TO 'team404user'@'%';

FLUSH PRIVILEGES;


-- Create ProjectDB table
CREATE TABLE ProjectDB (
    ID INT PRIMARY KEY AUTO_INCREMENT,
    startTime DATETIME NOT NULL,
    stopTime DATETIME,
    projectType VARCHAR(20) CHECK (projectType IN ('sniff_external', 'sniff_internal', 'heatmap'))
);

-- Create IngestDB table
CREATE TABLE IngestDB (
    ID INT PRIMARY KEY AUTO_INCREMENT,
    projectID INT NOT NULL,
    captureTime DATETIME NOT NULL,
    srcMac VARCHAR(17) NOT NULL,  -- MAC address format: XX:XX:XX:XX:XX:XX
    dstMac VARCHAR(17),
    SSID VARCHAR(255),
    encType VARCHAR(10) CHECK (encType IN ('Public', 'WPA', 'WPA2', 'WPA3')),
    authMode VARCHAR(20) CHECK (authMode IN ('PSK', 'Enterprise')),
    gpsLat INT,
    gpsLong INT,
    strength INT,
    contentLength INT,  -- Length in Bytes
    typeExternal VARCHAR(50),  -- DataFrame / RST / CST / Broadcast (maybe more)
    typeInternal VARCHAR(20), -- Should be like TCP, UDP, HTTP, DNS etc..
    srcIP VARCHAR(45),  -- IPv4 or IPv6
    dstIP VARCHAR(45),  -- IPv4 or IPv6
    srcPort INT CHECK (srcPort >= 0 AND srcPort <= 65535),
    dstPort INT CHECK (dstPort >= 0 AND dstPort <= 65535),
    sniffType VARCHAR(10) CHECK (sniffType IN ('internal', 'external')),
    
    -- Foreign key constraint
    CONSTRAINT fk_project FOREIGN KEY (projectID) REFERENCES ProjectDB(ID)
);
