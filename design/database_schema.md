# Database Schema for CVE and Exploit Storage

This document defines the database schema for storing CVE and exploit data in the CMS Vulnerability Scanner tool.

## Overview

The database will store vulnerability information, exploit details, and relationships between vulnerabilities and CMS components. It will be implemented using SQLite for portability and ease of deployment.

## Schema Design

### Tables

#### 1. Vulnerabilities

Stores information about known vulnerabilities.

```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_score REAL,
    published_date TEXT,
    last_modified_date TEXT,
    cwe_id TEXT,
    references_json TEXT,
    affected_software_json TEXT,
    remediation TEXT,
    UNIQUE(cve_id)
);

CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
```

#### 2. CMS

Stores information about supported CMS platforms.

```sql
CREATE TABLE cms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    vendor TEXT,
    website TEXT,
    description TEXT,
    UNIQUE(name)
);
```

#### 3. Components

Stores information about CMS components (plugins, themes, modules).

```sql
CREATE TABLE components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cms_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT CHECK (type IN ('plugin', 'theme', 'module', 'core', 'other')),
    description TEXT,
    website TEXT,
    FOREIGN KEY (cms_id) REFERENCES cms(id),
    UNIQUE(cms_id, name, type)
);

CREATE INDEX idx_components_cms_id ON components(cms_id);
CREATE INDEX idx_components_name ON components(name);
CREATE INDEX idx_components_type ON components(type);
```

#### 4. Component Versions

Stores version information for components.

```sql
CREATE TABLE component_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    release_date TEXT,
    FOREIGN KEY (component_id) REFERENCES components(id),
    UNIQUE(component_id, version)
);

CREATE INDEX idx_component_versions_component_id ON component_versions(component_id);
```

#### 5. Vulnerability Affects

Maps vulnerabilities to affected component versions.

```sql
CREATE TABLE vulnerability_affects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,
    component_id INTEGER NOT NULL,
    version_range TEXT NOT NULL,
    fixed_in TEXT,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),
    FOREIGN KEY (component_id) REFERENCES components(id),
    UNIQUE(vulnerability_id, component_id, version_range)
);

CREATE INDEX idx_vulnerability_affects_vulnerability_id ON vulnerability_affects(vulnerability_id);
CREATE INDEX idx_vulnerability_affects_component_id ON vulnerability_affects(component_id);
```

#### 6. Exploits

Stores exploit information for vulnerabilities.

```sql
CREATE TABLE exploits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    author TEXT,
    type TEXT CHECK (type IN ('rce', 'sqli', 'xss', 'csrf', 'lfi', 'rfi', 'auth_bypass', 'other')),
    code TEXT,
    url TEXT,
    exploit_db_id TEXT,
    metasploit_module TEXT,
    published_date TEXT,
    reliability REAL CHECK (reliability >= 0 AND reliability <= 1),
    requirements TEXT,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
);

CREATE INDEX idx_exploits_vulnerability_id ON exploits(vulnerability_id);
CREATE INDEX idx_exploits_type ON exploits(type);
```

#### 7. Fingerprints

Stores fingerprint information for CMS and component detection.

```sql
CREATE TABLE fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER NOT NULL,
    version_id INTEGER,
    fingerprint_type TEXT CHECK (fingerprint_type IN ('file', 'header', 'body', 'meta', 'other')),
    fingerprint_data TEXT NOT NULL,
    confidence REAL CHECK (confidence >= 0 AND confidence <= 1),
    FOREIGN KEY (component_id) REFERENCES components(id),
    FOREIGN KEY (version_id) REFERENCES component_versions(id)
);

CREATE INDEX idx_fingerprints_component_id ON fingerprints(component_id);
CREATE INDEX idx_fingerprints_version_id ON fingerprints(version_id);
```

#### 8. Database Metadata

Stores metadata about the database itself.

```sql
CREATE TABLE database_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    last_updated TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT,
    record_count INTEGER
);
```

## Data Sources

The database will be populated from the following sources:

1. **National Vulnerability Database (NVD)**
   - Primary source for CVE information
   - Provides CVSS scores and CWE classifications
   - API: https://nvd.nist.gov/developers/vulnerabilities

2. **WPScan Vulnerability Database**
   - Specialized for WordPress vulnerabilities
   - API: https://wpscan.com/api

3. **Exploit Database**
   - Collection of exploits for known vulnerabilities
   - API: https://www.exploit-db.com/api

4. **Patchstack Database**
   - Vulnerabilities for WordPress, Joomla, and Drupal
   - API: https://patchstack.com/database/api

5. **GitHub Security Advisories**
   - Community-reported vulnerabilities
   - API: https://docs.github.com/en/rest/security-advisories

## Data Collection Process

1. **Initial Population**
   - Bulk import from NVD data feeds
   - Filter for CMS-related vulnerabilities
   - Enrich with data from specialized sources

2. **Regular Updates**
   - Daily incremental updates from NVD
   - Weekly full refresh from specialized sources
   - Version-specific updates when new CMS versions are released

3. **Data Validation**
   - Cross-reference between sources
   - Validate version ranges and affected components
   - Verify exploit functionality where possible

## Data Access Patterns

The database is optimized for the following common queries:

1. **Vulnerability Lookup by Component**
   ```sql
   SELECT v.* FROM vulnerabilities v
   JOIN vulnerability_affects va ON v.id = va.vulnerability_id
   JOIN components c ON va.component_id = c.id
   WHERE c.name = ? AND c.type = ?;
   ```

2. **Exploit Lookup by CVE**
   ```sql
   SELECT e.* FROM exploits e
   JOIN vulnerabilities v ON e.vulnerability_id = v.id
   WHERE v.cve_id = ?;
   ```

3. **Component Version Vulnerability Check**
   ```sql
   SELECT v.* FROM vulnerabilities v
   JOIN vulnerability_affects va ON v.id = va.vulnerability_id
   JOIN components c ON va.component_id = c.id
   WHERE c.name = ? AND c.type = ?
   AND ? BETWEEN va.version_range AND COALESCE(va.fixed_in, '99999.99999.99999');
   ```

4. **Fingerprint Matching**
   ```sql
   SELECT c.*, cv.version FROM components c
   JOIN fingerprints f ON c.id = f.component_id
   LEFT JOIN component_versions cv ON f.version_id = cv.id
   WHERE f.fingerprint_type = ? AND f.fingerprint_data LIKE ?;
   ```

## Implementation Notes

1. **Version Comparison**
   - Implement semantic versioning comparison for accurate version range checks
   - Handle non-standard version formats (e.g., "4.7.x")

2. **JSON Storage**
   - Store complex data structures (references, affected software) as JSON
   - Use JSON functions for querying when available

3. **Data Synchronization**
   - Implement conflict resolution for data from multiple sources
   - Prioritize sources based on reliability and specificity

4. **Performance Considerations**
   - Use prepared statements for all queries
   - Implement caching for frequently accessed data
   - Consider denormalization for performance-critical queries

5. **Offline Operation**
   - Package a baseline database with the tool
   - Support operation without internet connectivity
   - Provide manual update mechanisms

This schema provides a comprehensive foundation for storing and accessing vulnerability and exploit data while maintaining relationships between vulnerabilities, CMS platforms, and their components.
