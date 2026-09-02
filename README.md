    # Redirect Chain Analyzer — Offline Web Application Security Tool

    [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
    [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
    [![Offline](https://img.shields.io/badge/mode-offline%20first-important.svg)](#)
    [![secintel](https://img.shields.io/badge/schema-secintel%20v1-purple.svg)](https://github.com/reshot2005/secintel-core)
    [![GitHub](https://img.shields.io/badge/github-reshot2005%2Fredirect-chain-analyzer-black.svg)](https://github.com/reshot2005/redirect-chain-analyzer)

    > **Trace HTTP redirect chains — detect open redirects, mixed HTTP/HTTPS hops, and unsafe redirect chains for web security testing.**

    **Category:** Web Application Security  
    **Collection phase tool:** 9/15  
    **Schema:** [secintel-core](https://github.com/reshot2005/secintel-core) v1  
    **Repository:** https://github.com/reshot2005/redirect-chain-analyzer  
    **Author account:** [reshot2005](https://github.com/reshot2005)

    ## Why Redirect Chain Analyzer ranks for security search

    Redirect Chain Analyzer is an **offline-first**, research-grade **web application security** utility designed for practitioners who need reproducible analysis without uploading sensitive artifacts to SaaS scanners. It emits structured findings through the shared **secintel** evidence taxonomy (OBSERVED / DERIVED / INFERRED / CORRELATED / VERIFIED) so results are auditable, exportable, and CI-friendly.

    ### Primary SEO keywords
    `open redirect, redirect chain, HTTP redirect security, mixed content redirects, URL redirect attack`

    ### Topics
    `web-security` `appsec` `owasp` `cybersecurity` `pentesting` `bug-bounty` `http-security` `security-tools` `python` `offline-security` `open-redirect` `url-security`

    ## What problem does this solve?

    Follow redirect chains and flag open-redirect risks plus insecure protocol downgrades.

    Chain-aware analysis vs single Location checks.

    ## Key features

    - Redirect chain tracing
- Open-redirect heuristics
- Mixed HTTP/HTTPS detection
- Chain visualization summary
- Evidence excerpts

    ## Ideal use cases

    - Test login redirect params
- Find HTTPS downgrades
- Bug bounty redirect hunts

    ## Who should use this

    - Security engineers & AppSec / NetSec specialists
    - SOC / DFIR / malware analysts (as applicable)
    - Bug bounty hunters and penetration testers
    - DevSecOps teams needing offline/air-gapped tooling
    - Students and researchers learning web application security

    ## Quick start

    ```bash
    git clone https://github.com/reshot2005/redirect-chain-analyzer.git
    cd redirect-chain-analyzer
    python3.12 -m venv .venv
    source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
    pip install -e ../secintel-core  # or: pip install -e git+https://github.com/reshot2005/secintel-core.git#egg=secintel-core
    pip install -e ".[dev]"

    redirect-chain-analyzer analyze sample_data --json
    redirect-chain-analyzer analyze sample_data --html report.html
    redirect-chain-analyzer version
    ```

    ### Exports for interoperability

    ```bash
    redirect-chain-analyzer analyze sample_data \
      --json --html report.html --csv findings.csv --sarif results.sarif
    ```

    ## Evidence quality & reproducibility

    - Findings follow **secintel** classification rules (confidence only where schema allows).
    - Provenance includes tool version, config hash, and input integrity metadata.
    - Set `SECINTEL_SOURCE_DATE_EPOCH` for deterministic timestamps in CI.

    ```bash
    export SECINTEL_SOURCE_DATE_EPOCH=1704067200
    redirect-chain-analyzer analyze sample_data --json
    ```

    ## Development

    ```bash
    ruff check src tests
    mypy src
    pytest
    ```

    ## Related tools in this collection

    Browse more offline security research tools by [reshot2005](https://github.com/reshot2005?tab=repositories): network security, web AppSec, DevSecOps, digital forensics, and static malware analysis — each in its own public repository with the same secintel reporting contract.

    ## License

    MIT — free for research, education, and commercial use with attribution preserved.

    ---

    ### Discoverability blurb (search engines & GitHub)

    **Redirect Chain Analyzer (redirect-chain-analyzer)** — Trace HTTP redirect chains — detect open redirects, mixed HTTP/HTTPS hops, and unsafe redirect chains for web security testing. Search terms: open redirect, redirect chain, HTTP redirect security, mixed content redirects, URL redirect attack. Open-source, MIT-licensed, Python 3.12, offline cybersecurity tool by reshot2005.
