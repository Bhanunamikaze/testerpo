# Workflow Diagrams - Passive Reconnaissance Tool

This document contains visual workflow diagrams using Mermaid JS to illustrate the tool's architecture, execution flow, and data processing pipeline.

---

## 1. High-Level Execution Flow

```mermaid
graph TB
    Start([Start Scan]) --> Validate[Input Validation]
    Validate -->|Valid| Init[Initialize Scanner]
    Validate -->|Invalid| Error1[Display Errors & Exit]

    Init --> Phase1[Phase 1: Scope Building]
    Phase1 --> Phase2[Phase 2: Asset Discovery]
    Phase2 --> Phase3[Phase 3: Content Collection]
    Phase3 --> Phase4[Phase 4: Detection Engines]
    Phase4 --> Phase5[Phase 5: Risk Scoring]
    Phase5 --> Phase6[Phase 6: Output Generation]

    Phase6 --> Summary[Print Summary]
    Summary --> End([Scan Complete])

    Error1 --> End

    style Start fill:#90EE90
    style End fill:#FFB6C1
    style Validate fill:#FFE4B5
    style Error1 fill:#FF6B6B
```

---

## 2. Detailed Phase-by-Phase Workflow

```mermaid
flowchart TD
    subgraph Phase1[Phase 1: Scope Building]
        P1A[Load Target Domains] --> P1B[Generate TLD Variants]
        P1B --> P1C[Add Environment Prefixes]
        P1C --> P1D[Add SaaS Patterns]
        P1D --> P1E[Load Organization Names]
        P1E --> P1F[Final Scope: 100+ Domains]
    end

    subgraph Phase2[Phase 2: Asset Discovery]
        P2A[Certificate Transparency Logs] --> P2AA[crt.sh API]
        P2A --> P2AB[CertSpotter API]
        P2B[Search Engine Dorking] --> P2BA[Browser-Based Collector]
        P2B --> P2BB[API-Based Collector]
        P2C[GitHub/GitLab Repos]
        P2D[Cloud Storage Buckets]
        P2E[Paste Sites]
    end

    subgraph Phase3[Phase 3: Content Collection]
        P3A[Normalize URLs] --> P3B[Deduplicate Assets]
        P3B --> P3C[Fetch Content]
        P3C --> P3D[Extract Metadata]
        P3D --> P3E[Cache Results]
    end

    subgraph Phase4[Phase 4: Detection Engines]
        P4A[Secret Detector] --> P4AA[Regex Matching]
        P4AA --> P4AB[Entropy Analysis]
        P4AB --> P4AC[Context Validation]

        P4B[Vulnerability Detector] --> P4BA[Error Messages]
        P4BA --> P4BB[Debug Modes]
        P4BB --> P4BC[Exposed Files]

        P4C[Admin Panel Detector] --> P4CA[Common Paths]
        P4CA --> P4CB[DevOps Tools]
    end

    subgraph Phase5[Phase 5: Risk Scoring]
        P5A[Calculate Risk Score] --> P5B[Severity Classification]
        P5B --> P5C[Confidence Score]
        P5C --> P5D[Priority Ranking]
    end

    subgraph Phase6[Phase 6: Output Generation]
        P6A[JSON Export] --> P6AA[findings.json]
        P6B[CSV Export] --> P6BB[findings.csv]
        P6C[HTML Report] --> P6CC[report.html]
        P6D[Critical Findings] --> P6DD[critical_findings.json]
    end

    Phase1 --> Phase2
    Phase2 --> Phase3
    Phase3 --> Phase4
    Phase4 --> Phase5
    Phase5 --> Phase6

    style Phase1 fill:#E1F5FF
    style Phase2 fill:#FFF9C4
    style Phase3 fill:#F0F4C3
    style Phase4 fill:#FFE0B2
    style Phase5 fill:#FFCCBC
    style Phase6 fill:#D1C4E9
```

---

## 3. Browser-Based Search Engine Collector Architecture

```mermaid
graph TB
    subgraph BrowserPool[Browser Pool Manager]
        BP1[Browser 1<br/>12 Tabs]
        BP2[Browser 2<br/>12 Tabs]
        BP3[Browser 3<br/>12 Tabs]
    end

    Config[Configuration] --> BrowserPool

    subgraph Stealth[Stealth Features]
        S1[WebDriver Bypass]
        S2[Random User Agents]
        S3[Viewport Randomization]
        S4[Realistic Headers]
    end

    Stealth --> BrowserPool

    Dorks[250+ Google Dorks<br/>16 Categories] --> TaskQueue[Task Queue]

    TaskQueue --> BP1
    TaskQueue --> BP2
    TaskQueue --> BP3

    BP1 --> CAPTCHA{CAPTCHA<br/>Detected?}
    BP2 --> CAPTCHA
    BP3 --> CAPTCHA

    CAPTCHA -->|Yes| Skip[Skip Query<br/>Log Warning]
    CAPTCHA -->|No| Parse[Parse Results<br/>Extract URLs]

    Parse --> Cache[Cache Manager<br/>TTL: 1 hour]
    Cache --> Results[Findings List]

    Skip --> Results

    Results --> Next[Next Batch]

    style BrowserPool fill:#B3E5FC
    style Stealth fill:#C5E1A5
    style TaskQueue fill:#FFECB3
    style CAPTCHA fill:#FFCCBC
    style Cache fill:#CE93D8
```

---

## 4. Data Collection Architecture

```mermaid
flowchart LR
    subgraph Collectors[Data Collectors]
        direction TB
        CT[Certificate<br/>Transparency]
        SE[Search<br/>Engines]
        GH[GitHub/<br/>GitLab]
        CS[Cloud<br/>Storage]
        PS[Paste<br/>Sites]
        BR[Browser<br/>Collector]
    end

    subgraph Sources[Data Sources]
        direction TB
        CRT[crt.sh]
        CERT[CertSpotter]
        GOOG[Google]
        BING[Bing]
        GHA[GitHub API]
        S3[AWS S3]
        GCS[GCP Storage]
        PB[Pastebin]
    end

    subgraph Processing[Processing Layer]
        direction TB
        NORM[URL Normalizer]
        DEDUP[Deduplicator]
        CACHE[Cache Manager]
        RATE[Rate Limiter]
    end

    subgraph Storage[Storage]
        direction TB
        ASSETS[(Assets DB)]
        FINDINGS[(Findings DB)]
    end

    Sources --> Collectors
    Collectors --> Processing
    Processing --> Storage

    CT -.->|Query| CRT
    CT -.->|Query| CERT
    SE -.->|Dorks| GOOG
    SE -.->|Dorks| BING
    BR -.->|Browser| GOOG
    GH -.->|API| GHA
    CS -.->|Enumerate| S3
    CS -.->|Enumerate| GCS
    PS -.->|Scrape| PB

    style Collectors fill:#90CAF9
    style Sources fill:#A5D6A7
    style Processing fill:#FFE082
    style Storage fill:#CE93D8
```

---

## 5. Secret Detection Pipeline

```mermaid
graph TB
    Input[Content Input<br/>URLs, Code, Files] --> Extract[Extract Scannable Content]

    Extract --> Patterns[Load 80+ Secret Patterns]

    Patterns --> Regex{Regex<br/>Match?}

    Regex -->|No Match| Skip[Skip to Next]
    Regex -->|Match Found| Entropy{Calculate<br/>Shannon Entropy}

    Entropy -->|Low Entropy| FP1[Likely False Positive]
    Entropy -->|High Entropy| Context{Check<br/>Context}

    Context -->|Test Values| FP2[Common Test Pattern]
    Context -->|Repeated Chars| FP3[Invalid Pattern]
    Context -->|Valid Context| Validate{Validation<br/>Checks}

    Validate --> Score[Calculate Confidence Score]
    Score --> Classify[Classify Severity]

    Classify --> Critical[Critical: AWS Keys, DB Credentials]
    Classify --> High[High: API Keys, Tokens]
    Classify --> Medium[Medium: Potential Secrets]

    Critical --> Report[Add to Findings]
    High --> Report
    Medium --> Report

    FP1 --> Skip
    FP2 --> Skip
    FP3 --> Skip
    Skip --> Next[Process Next Content]

    Report --> Output[Secret Findings<br/>with Context]

    style Input fill:#E1F5FF
    style Patterns fill:#FFF9C4
    style Regex fill:#FFE0B2
    style Entropy fill:#FFCCBC
    style Context fill:#F8BBD0
    style Critical fill:#FF5252
    style High fill:#FF9800
    style Medium fill:#FFC107
    style Output fill:#4CAF50
```

---

## 6. Module Dependency Graph

```mermaid
graph LR
    subgraph Core[Core Modules]
        Main[passive_recon.py<br/>Main Orchestrator]
    end

    subgraph Seeds[Scope Building]
        Scope[scope_builder.py]
    end

    subgraph Collectors[Data Collectors]
        CT[certificate_transparency.py]
        SE[search_engine.py]
        BSE[browser_search_engine.py]
        GH[github_collector.py]
        Cloud[cloud_storage.py]
        Paste[paste_sites.py]
    end

    subgraph Detectors[Detection Engines]
        Secret[secret_detector.py]
        Vuln[vulnerability_detector.py]
        Admin[admin_panel_detector.py]
    end

    subgraph Utils[Utility Modules]
        Cache[cache_manager.py]
        Rate[rate_limiter.py]
        Browser[browser_pool.py]
        Valid[validator.py]
    end

    subgraph Normalizers[Normalization]
        URLNorm[url_normalizer.py]
    end

    subgraph Scorers[Risk Scoring]
        Risk[risk_scorer.py]
    end

    subgraph Outputs[Output Handlers]
        Output[output_handler.py]
    end

    subgraph Rules[Rule Files]
        Dorks[google_dorks.json<br/>250+ dorks]
        Patterns[secret_patterns.json<br/>80+ patterns]
    end

    Main --> Scope
    Main --> Collectors
    Main --> Detectors
    Main --> Normalizers
    Main --> Scorers
    Main --> Outputs

    Collectors --> Utils
    BSE --> Browser
    Main --> Valid

    Secret --> Patterns
    Collectors --> Dorks

    Detectors --> URLNorm
    Collectors --> Cache
    Collectors --> Rate

    style Core fill:#FF6B6B
    style Seeds fill:#4ECDC4
    style Collectors fill:#95E1D3
    style Detectors fill:#F3A683
    style Utils fill:#FDCB6E
    style Normalizers fill:#A29BFE
    style Scorers fill:#FD79A8
    style Outputs fill:#00B894
    style Rules fill:#74B9FF
```

---

## 7. Risk Scoring Algorithm

```mermaid
graph TB
    Finding[Finding Detected] --> Category{Category<br/>Type}

    Category -->|Secret| CatScore1[Base Score: 10]
    Category -->|Vulnerability| CatScore2[Base Score: 8]
    Category -->|Admin Panel| CatScore3[Base Score: 6]
    Category -->|Exposure| CatScore4[Base Score: 4]

    CatScore1 --> Severity{Severity<br/>Level}
    CatScore2 --> Severity
    CatScore3 --> Severity
    CatScore4 --> Severity

    Severity -->|Critical| SevMult1[Multiplier: 1.0]
    Severity -->|High| SevMult2[Multiplier: 0.8]
    Severity -->|Medium| SevMult3[Multiplier: 0.6]
    Severity -->|Low| SevMult4[Multiplier: 0.4]

    SevMult1 --> Confidence{Confidence<br/>Score}
    SevMult2 --> Confidence
    SevMult3 --> Confidence
    SevMult4 --> Confidence

    Confidence -->|High: 0.8-1.0| ConfMult1[Multiplier: 1.0]
    Confidence -->|Medium: 0.5-0.8| ConfMult2[Multiplier: 0.8]
    Confidence -->|Low: 0-0.5| ConfMult3[Multiplier: 0.6]

    ConfMult1 --> Calculate[Final Risk Score<br/>= Base × Severity × Confidence]
    ConfMult2 --> Calculate
    ConfMult3 --> Calculate

    Calculate --> Classify{Classify<br/>Final Score}

    Classify -->|9.0-10.0| Critical[Critical Risk]
    Classify -->|7.0-8.9| High[High Risk]
    Classify -->|5.0-6.9| Medium[Medium Risk]
    Classify -->|3.0-4.9| Low[Low Risk]
    Classify -->|0-2.9| Info[Informational]

    Critical --> Prioritize[Priority Queue<br/>for Reporting]
    High --> Prioritize
    Medium --> Prioritize
    Low --> Prioritize
    Info --> Prioritize

    style Finding fill:#E1F5FF
    style Category fill:#FFF9C4
    style Severity fill:#FFE0B2
    style Confidence fill:#FFCCBC
    style Critical fill:#FF5252
    style High fill:#FF9800
    style Medium fill:#FFC107
    style Low fill:#4CAF50
    style Info fill:#2196F3
```

---

## 8. Configuration & Validation Flow

```mermaid
flowchart TD
    Start([User Runs Script]) --> Args[Parse CLI Arguments]

    Args --> ValidFlag{Skip<br/>Validation?}

    ValidFlag -->|Yes| Load[Load Configuration]
    ValidFlag -->|No| Validate[Run Validators]

    Validate --> V1[Validate Targets]
    V1 --> V2[Validate Config File]
    V2 --> V3[Validate Config Values]
    V3 --> V4[Validate Scope File]
    V4 --> V5[Validate Output Dir]

    V5 --> Errors{Any<br/>Errors?}

    Errors -->|Yes| Display[Display Errors & Exit]
    Errors -->|No| Warnings{Any<br/>Warnings?}

    Warnings -->|Yes| ShowWarn[Display Warnings]
    Warnings -->|No| Load
    ShowWarn --> Load

    Load --> Init[Initialize Modules]
    Init --> ConfigMods[Configure Modules]

    ConfigMods --> BrowserMode{Use<br/>Browser?}

    BrowserMode -->|Yes| BrowserCheck{Playwright<br/>Available?}
    BrowserMode -->|No| APIMode[Use API Collectors]

    BrowserCheck -->|Yes| BrowserMode2[Use Browser Collectors]
    BrowserCheck -->|No| Fallback[Fallback to API<br/>+ Warning]

    BrowserMode2 --> Execute[Execute Scan]
    APIMode --> Execute
    Fallback --> Execute

    Execute --> Success([Scan Complete])
    Display --> End([Exit with Error])

    style Start fill:#90EE90
    style Validate fill:#FFE4B5
    style Errors fill:#FF6B6B
    style Warnings fill:#FFA500
    style Execute fill:#87CEEB
    style Success fill:#98FB98
    style End fill:#FFB6C1
```

---

## 9. Output Generation Pipeline

```mermaid
graph TB
    Findings[All Findings<br/>Deduplicated] --> Sort[Sort by Risk Score]

    Sort --> Filter{Apply<br/>Filters?}

    Filter -->|Yes| MinConf[Min Confidence Filter]
    Filter -->|No| Export

    MinConf --> ExcludeLow{Exclude<br/>Low Severity?}
    ExcludeLow -->|Yes| FilterOut[Remove Low Severity]
    ExcludeLow -->|No| Export[Export Pipeline]

    FilterOut --> Export

    subgraph ExportFormats[Export Formats]
        direction TB
        JSON[JSON Export]
        CSV[CSV Export]
        HTML[HTML Report]
    end

    Export --> ExportFormats

    JSON --> JSONFile[findings.json<br/>Complete Data]
    CSV --> CSVFile[findings.csv<br/>Flattened Data]
    HTML --> HTMLFile[report.html<br/>Visual Report]

    subgraph HTMLReport[HTML Report Contents]
        direction TB
        Summary[Executive Summary]
        SevChart[Severity Distribution]
        Timeline[Discovery Timeline]
        Details[Detailed Findings]
        Evidence[Evidence Snippets]
    end

    HTMLFile --> HTMLReport

    Findings --> Critical{Critical/High<br/>Findings?}

    Critical -->|Yes| CritFile[critical_findings.json<br/>Priority Items]
    Critical -->|No| Skip[Skip Critical Export]

    subgraph Outputs[Output Directory]
        JSONFile
        CSVFile
        HTMLFile
        CritFile
        LogFile[passive_recon.log]
    end

    CritFile --> Summary2[Print Summary Stats]
    Skip --> Summary2

    Summary2 --> Done([Outputs Complete])

    style Findings fill:#E1F5FF
    style ExportFormats fill:#FFF9C4
    style HTMLReport fill:#FFE0B2
    style Outputs fill:#C8E6C9
    style Done fill:#90EE90
```

---

## 10. Concurrent Execution Model (Browser Mode)

```mermaid
sequenceDiagram
    participant Main as Main Thread
    participant BP as Browser Pool
    participant B1 as Browser 1
    participant B2 as Browser 2
    participant B3 as Browser 3
    participant Tasks as Task Queue

    Main->>BP: Initialize Pool (3 browsers, 12 tabs each)
    BP->>B1: Launch Browser 1
    BP->>B2: Launch Browser 2
    BP->>B3: Launch Browser 3

    Main->>Tasks: Queue 250+ Dork Queries

    loop Concurrent Execution
        Tasks->>BP: Get Next Batch (36 tasks)

        par Browser 1 (12 tabs)
            BP->>B1: Execute Queries 1-12
            B1->>B1: Tab 1-12 Concurrent
            B1-->>BP: Return Results
        and Browser 2 (12 tabs)
            BP->>B2: Execute Queries 13-24
            B2->>B2: Tab 1-12 Concurrent
            B2-->>BP: Return Results
        and Browser 3 (12 tabs)
            BP->>B3: Execute Queries 25-36
            B3->>B3: Tab 1-12 Concurrent
            B3-->>BP: Return Results
        end

        BP->>BP: Check for CAPTCHA
        BP->>BP: Apply Rate Limiting
        BP-->>Main: Batch Results

        Main->>Main: Process & Cache Results
    end

    Main->>BP: Close Pool
    BP->>B1: Close Browser
    BP->>B2: Close Browser
    BP->>B3: Close Browser

    BP-->>Main: Cleanup Complete
```

---

## 11. Error Handling & Recovery Flow

```mermaid
graph TB
    Start([Operation Start]) --> Try{Try<br/>Operation}

    Try -->|Success| Log1[Log Success]
    Try -->|Exception| Catch{Exception<br/>Type}

    Catch -->|Network Error| Retry{Retry<br/>Count < Max?}
    Catch -->|Rate Limited| Wait[Exponential Backoff]
    Catch -->|CAPTCHA| Skip1[Skip Query<br/>Log Warning]
    Catch -->|Timeout| Retry2{Retry<br/>Count < Max?}
    Catch -->|Permission Error| Fatal1[Log Error<br/>Exit]
    Catch -->|File Not Found| Fatal2[Log Error<br/>Exit]
    Catch -->|Validation Error| Fatal3[Display Errors<br/>Exit]
    Catch -->|Keyboard Interrupt| Graceful[Graceful Shutdown]
    Catch -->|Unknown Error| LogErr[Log Full Stack Trace]

    Retry -->|Yes| Backoff1[Wait 2^n seconds]
    Retry -->|No| GiveUp[Log Failure<br/>Continue]

    Retry2 -->|Yes| Backoff2[Wait 2^n seconds]
    Retry2 -->|No| GiveUp

    Backoff1 --> Try
    Backoff2 --> Try
    Wait --> Try

    Skip1 --> Next[Continue Next Task]
    GiveUp --> Next
    LogErr --> Next

    Log1 --> Success([Operation Complete])
    Next --> Success

    Fatal1 --> End([Exit: Error 1])
    Fatal2 --> End
    Fatal3 --> End

    Graceful --> Cleanup[Cleanup Resources]
    Cleanup --> SavePartial[Save Partial Results]
    SavePartial --> GracefulEnd([Exit: Code 130])

    style Start fill:#90EE90
    style Try fill:#E1F5FF
    style Catch fill:#FFE4B5
    style Fatal1 fill:#FF5252
    style Fatal2 fill:#FF5252
    style Fatal3 fill:#FF5252
    style Graceful fill:#FFA726
    style Success fill:#66BB6A
    style End fill:#FFB6C1
    style GracefulEnd fill:#FF9800
```

---

## 12. Complete System Architecture

```mermaid
graph TB
    subgraph UserInterface[User Interface Layer]
        CLI[Command Line Interface]
        Validator[Input Validator]
        Config[Configuration Loader]
    end

    subgraph Core[Core Orchestration Layer]
        Main[Main Scanner<br/>passive_recon.py]
        Phase[Phase Manager]
        Logger[Logging System]
    end

    subgraph Collection[Data Collection Layer]
        Scope[Scope Builder]
        CT[CT Logs Collector]
        SE[Search Engine Collector]
        BSE[Browser Collector]
        GH[GitHub Collector]
        CS[Cloud Collector]
        PS[Paste Collector]
    end

    subgraph Processing[Processing Layer]
        Norm[URL Normalizer]
        Dedup[Deduplicator]
        Cache[Cache Manager]
        Rate[Rate Limiter]
    end

    subgraph Detection[Detection Layer]
        Secret[Secret Detector<br/>80+ Patterns]
        Vuln[Vulnerability Detector]
        Admin[Admin Panel Detector]
    end

    subgraph Analysis[Analysis Layer]
        Risk[Risk Scorer]
        Priority[Priority Ranker]
        Filter[Filter Engine]
    end

    subgraph Output[Output Layer]
        JSON[JSON Exporter]
        CSV[CSV Exporter]
        HTML[HTML Reporter]
        Critical[Critical Filter]
    end

    subgraph External[External Resources]
        BrowserPool[Browser Pool<br/>Playwright]
        Rules[Rules Files<br/>Dorks & Patterns]
        APIs[External APIs<br/>GitHub, Search]
    end

    UserInterface --> Core
    Core --> Collection
    Collection --> Processing
    Processing --> Detection
    Detection --> Analysis
    Analysis --> Output

    Collection -.-> External
    Detection -.-> External
    Processing -.-> External

    Output --> Results[(Output Files<br/>results/)]

    style UserInterface fill:#E3F2FD
    style Core fill:#FFF3E0
    style Collection fill:#E8F5E9
    style Processing fill:#F3E5F5
    style Detection fill:#FCE4EC
    style Analysis fill:#FFF9C4
    style Output fill:#E0F2F1
    style External fill:#EFEBE9
    style Results fill:#C5CAE9
```

---

## Usage in Documentation

These diagrams can be embedded in GitHub, GitLab, and other Markdown viewers that support Mermaid JS.

### Rendering:
- **GitHub:** Native support (automatically renders)
- **GitLab:** Native support
- **VS Code:** Use Mermaid preview extensions
- **Online:** Copy to [Mermaid Live Editor](https://mermaid.live/)

### Integration Examples:

```markdown
# Quick Reference in README.md

See the [high-level execution flow](WORKFLOW_DIAGRAMS.md#1-high-level-execution-flow) for an overview.

# In Documentation
For detailed architecture, refer to:
- [Module Dependencies](WORKFLOW_DIAGRAMS.md#6-module-dependency-graph)
- [Browser Architecture](WORKFLOW_DIAGRAMS.md#3-browser-based-search-engine-collector-architecture)
- [Secret Detection Pipeline](WORKFLOW_DIAGRAMS.md#5-secret-detection-pipeline)
```

---

**Generated:** 2025-10-29
**Version:** 1.0.0
**Tool:** Passive Reconnaissance Tool for External Pentesting
