## Design Document: Cloud Recon Detection
Owner: Daniel Oliver · Date: 09-15-2025

**Summary:**
This design proposes a local CLI tool for detecting reconnaissance (recon) activity in AWS CloudTrail logs using a combination of machine learning and rules-based detection. The tool ingests CloudTrail logs and outputs whether suspicious behavior was detected, the suspected identity, the relevant time frame, and supporting evidence. This tool addresses the problems described in this challenge: https://github.com/gravitational/careers/blob/main/challenges/ai-ml/challenge-1.md


## Section 1. Scope
**In scope:** 
Detect identities showing abnormal AccessDenied errors, unusual List/Describe* calls, or unexpected changes in IP addresses, AWS regions, or user agents.

**Out of scope:** 
External databases and high availability considerations are out of scope.

**Assumptions & constraints**

* Assumptions made include:
    * Data is provided in a json.gz format and parseable.
    * Logs include normal and anomalous activity.
    * Recon activity in the logs manifests as unusual spikes across different features.

* The relevant constraints are:
    * One week for design document submission (submission on 9/18),
    * and one week for implementation development (submission on 9/25).

## Section 2. Design Approach
### Section 2.1 Goals
After analyzing the logs, the tool should output the following information:
* Whether the suspicious activity was detected and the confidence level.
* The suspected identity.
* The time frame of the suspected recon activity.
* Key indicators (example logs/API calls).


### Section 2.2: System overview
**CloudTrail Logs**
* CloudTrail logs are provided by the user. The logs should be expected to cover a length of time that demonstrates normal periods of API behavior as well as anomalous behavior. Logs that strictly contain anomalous behavior exclusively may not lead to adequate recon detection.

**CLI**
* An input path containing the CloudTrail logs are provided to the CLI tool, as well as an output path for results to be saved. All other arguments are defaulted to and cannot currently be manipulated.

**Data Processing**
* The logs are partitioned into time windows and saved as parquet files.
* Features and metrics are calculated per-principal.

**Machine Learning Anomaly Detection Layer**

* Per-Principal detection
    * Highlight periods of unusual bursts of activity, relative to the principal’s provided history.
    * Used for capturing subtle patterns.

* Potential models: Unsupervised anomaly detection models (Local Outlier Factor, DBSCAN) or Z-score analysis
    * Unsupervised models can be used for identifying ‘normal behavior’ and labelling outliers.
        * These models don’t require training, which is beneficial given data is unlabelled.
    * Simple cases, such as bursts in AccessDenied errors, could use Z-score analysis to identify burst counts that are, for example, only 5% likely of occurring. Z-score analysis is beneficial in cases with limited available data.
    * Example: A principal which has a count of List* calls in a time window that are above a Z-score of 1.645 will be flagged as a suspicious identity.

**Rational**
* Rules can misclassify principals that legitimately change IPs or user agents; using per-principal baselines via ML reduces these false positives.
* Shortcoming of Z-score analysis: assumes that there is enough data to establish a mean and standard deviations.

**Rules-Based Identity Search**
* Used when ML methods aren’t applicable.
* Anomalous time windows can be queried with rules-based methods to isolate identities behind recon activities.
* Set thresholds are used by rules, removing relative considerations that ML methods could provide.
* Example: A principal which uses two or more IP addresses within a 15 minute time window will be flagged as a suspicious identity.
* Example: A principal with more than 20 AccessDenied errors will be flagged as a suspicious identity.

**Output**
* The output will be a json file, which would contain:
* Suspected Identity’s information: principalId, accessKey, arn
* Suspicious activity: eventName, eventType, eventSource
* Timeframe
* Supporting evidence: metrics, anomaly flags

### Section 2.3: Key decisions & rationale
**Data selection**
* Principals with too few datapoints (n=100, or below) will not be used for unsupervised classification models and will go to Z-score analysis.
* Principals with too few datapoints (n=30, or below) will not be used for Z-score analysis and go straight to the rules-based layer.

**Detectable Activities**
* Activities detected in this tool are limited due to the challenge timeline. They are all considered recon activities but don’t fully encapsulate all possible recon activities. 

## Section 3. Alternatives Evaluated
**Option A (chosen):**
* Pros: 
    * Machine Learning layer provides a method to create per-principal feature specific models.
    * Rules-based methods provide a fallback for when the ML layer can’t run due to limited data.
* Cons:
    * A two-layer process is more complex than a single-layer process.
    * Is dependent on immediate data provided, and can’t call on historical data to make decisions.

**Option B:**
* Incorporating Organization level detection as an addition to the Machine Learning layer. Pros include:
    * Excellent opportunity to identify cross-principal bursts of low-intensity scanning.
    * Per-principal models wouldn’t identify these.
    * The org-level model would as it detects aggregate anonymous behavior.
    * Highlight anomalous time windows across all principals.
    * Reduces noise by identifying the most anomalous time windows for further analysis. 
    * Model used: Local Outlier Factor (LOF) or other Unsupervised model
* Cons: For this challenge, detecting cross-principal bursts is out-of-scope so this model will not be included.

**Option C:**
* A tool with no machine learning layer and straight to a rules-based only design. Pros include:
    * Simple, streamlined design.
* Cons include:
    * Thresholds would require arbitrary selections that could have considerable impacts on precision and recall.

## Section 4. Proposed API
**Command:**
    
    $ recon scan --input_file <input_file_path.json.gz> --output_file <output_file_path>

**Example:**
    
    $ recon scan --input_file ~/challenge/data/log1.json.gz --output_file ~/challenge/outout/scan_result.json
* Exit codes: 0=ok, 1=anomalies found, >1=errors.

## Section 5. Security Considerations
**Data handling:**
* The tool processes only locally provided log files. 
* Ensure safe file I/O practices and avoid assumptions about file trustworthiness to prevent parsing errors.

**Secrets & keys:**
* No live AWS credentials or keys are required. 
* All analysis is on pre-downloaded, anonymized data (see Section 9. References, item no. 3).

**Abuse scenarios:**
* Input logs could be modified, treating them as untrusted input. 
* Use robust parsing and input validation to mitigate risks of malformed files or malicious payloads.

**Privacy:**
* Do not provide dataset’s IP addresses to IP blacklists, as they were anonymized and part of a test.

**Software Versioning:**
* Dependencies and CLI releases should be version-pinned and checksummed.
* A lightweight SBOM for reproducibility would be beneficial.

## Section 6. Implementation Details
**Feature table (per-principal):**
* Features: 
    * principalID, userAgent, sourceIPAddress, eventName, awsRegion, year, month, day, time, errorCode.

**Metrics:**
* Metrics monitored in this tool on a per-principal basis include:
    * totalCalls: total API calls.
    * denialCount: total denied requests. 
    * denialRate: denialCount/totalCalls 
    * ipCount: unique IP addresses count.
    * userAgentCount: unique user agents count. 
    * regionsCount: unique aws regions count. 
    * noveltyAlert: binary flag if first time ever IP, user agent,or AWS region detected for principal.  
    * listDescCount: List/Describe API calls count. 
    * listDescRate: listDescRate/totalCalls
    * listDescDenialCount: Denied List/Describe API calls count.
    * listDescDenialRate: listDescDenialCount/listDescCount

## Section 7. Risks & Mitigations
**Sparse principals**
* Fallback to rules-based methods when insufficient data for ML.

**Data drift**
* Use rolling windows and change point detection to adapt baselines.

**Memory constraints**
* Apply data limits on logs provided to the CLI tool.

## Section 8. Testing & Validation
* This application will make use of unit, data, and load tests.
* Finetuning: Time-window partitions and feature selection are important aspects of the tool’s success.
* Test datasets will be created for specific tasks.

## Section 9. References
1. AWS CloudTrail API Reference: https://docs.aws.amazon.com/pdfs/awscloudtrail/latest/APIReference/awscloudtrail-api.pdf
2. MITRE ATT&CK Tactics TA0043 Reconnaissance: https://attack.mitre.org/tactics/TA0043/
3. Summit Route – Public Dataset of CloudTrail Logs: https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/
4. GitHub – easttimor/aws-incident-response: https://github.com/easttimor/aws-incident-response

