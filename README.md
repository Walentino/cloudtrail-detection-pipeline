## Architecture

```mermaid
flowchart TD
    A[AWS API Call] --> B[CloudTrail]
    B --> C[S3 Bucket: walentino-cloudtrail-logs-2026]
    C -->|S3 Event Notification| D[SQS Queue: elastic-cloudtrail-queue]
    D -->|Lambda Event Source Mapping| E[Lambda: esf-cloudtrail-forwarder]
    E -->|Elasticsearch API| F[Elastic Security Serverless]
    F --> G[Index: cloudtrail-logs]
    G --> H[KQL Detection Rules]
    H --> I[Alerts Dashboard]

    subgraph AWS Cloud
        A
        B
        C
        D
        E
    end

    subgraph Elastic Cloud
        F
        G
        H
        I
    end
```

Phase 1: AWS Environment Setup
Objective: Establish the foundational AWS infrastructure for log generation and storage.

Component	Configuration	Purpose
AWS Account	Free Tier (457664479040)	All resources deployed in us-east-1
CloudTrail Trail	project-detection-trail	Records management events across all regions
Log Delivery S3 Bucket	walentino-cloudtrail-logs-2026	Receives compressed CloudTrail .json.gz log files
Bucket Policy	Allows cloudtrail.amazonaws.com to s3:PutObject	Grants CloudTrail permission to deliver logs
Validation:

CloudTrail trail status confirmed as "Logging"

Log files visible in S3 bucket under AWSLogs/457664479040/CloudTrail/

Downloaded and decompressed a sample log file — confirmed valid JSON with management event records

---

## Phase 1: AWS Environment Setup

**Objective:** Establish the foundational AWS infrastructure for log generation and storage.

| Component | Configuration | Purpose |
|-----------|---------------|---------|
| AWS Account | Free Tier (`457664479040`) | All resources deployed in us-east-1 |
| CloudTrail Trail | `project-detection-trail` | Records management events across all regions |
| Log Delivery S3 Bucket | `walentino-cloudtrail-logs-2026` | Receives compressed CloudTrail `.json.gz` log files |
| Bucket Policy | Allows `cloudtrail.amazonaws.com` to `s3:PutObject` | Grants CloudTrail permission to deliver logs |

**Validation:**
- CloudTrail trail status confirmed as "Logging"
- Log files visible in S3 bucket under `AWSLogs/457664479040/CloudTrail/`
- Downloaded and decompressed a sample log file — confirmed valid JSON with management event records

**Screenshots:**

![CloudTrail Trail](screenshots/Screenshot%202026-05-04%20at%209.28.11 AM.png)

![S3 Bucket](screenshots/Screenshot%202026-05-04%20at%209.29.37 AM.png)

![Bucket Policy](screenshots/Screenshot%202026-05-04%20at%209.30.33 AM.png)

---

## Phase 2: Vulnerable Resources

**Objective:** Deploy deliberately misconfigured AWS resources that simulate real-world cloud security risks. These serve as detection targets for Phase 4 rules.

### Resource 1: Public S3 Bucket

| Property | Value |
|----------|-------|
| Bucket Name | `target-data-leak-2026` |
| Public Access | Block all public access: **Off** |
| Bucket Policy | Allows `s3:GetObject` to `Principal: *` |
| Test File | `test-file.txt` ("This is a test file for detection validation") |

This simulates a common cloud misconfiguration: an S3 bucket unintentionally exposed to the internet. In a real attack, an adversary could enumerate and exfiltrate sensitive data.

### Resource 2: Over-Permissive IAM User

| Property | Value |
|----------|-------|
| User Name | `project-admin` |
| Inline Policy | `OverPermissivePolicy` |
| Allowed Actions | `iam:AttachUserPolicy` (all resources), `sts:AssumeRole` (all resources) |

This simulates an IAM user with excessive privileges. An attacker compromising these credentials could escalate to full AdministratorAccess.

**Screenshots:**

![S3 Public Access Off](screenshots/Screenshot%202026-05-04%20at%209.31.37 AM.png)

![S3 Bucket Policy](screenshots/Screenshot%202026-05-04%20at%209.31.52 AM.png)

![IAM User](screenshots/Screenshot%202026-05-04%20at%209.33.14 AM.png)

![Inline Policy](screenshots/Screenshot%202026-05-04%20at%209.33.26 AM.png)

