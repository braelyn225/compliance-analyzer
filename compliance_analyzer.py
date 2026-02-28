"""
GRC Compliance Gap Analyzer
Author: Braelyn Jones
Description: Reads a CSV of security controls, analyzes compliance gaps against
             ISO 27001 and NIST CSF frameworks, calculates risk scores, and
             generates an HTML executive report with charts and remediation priorities.
"""

import csv
import os
import sys
from datetime import datetime
from collections import Counter


# ──────────────────────────────────────────────────
# 1. DATA LOADING & VALIDATION
# ──────────────────────────────────────────────────

REQUIRED_COLUMNS = [
    "control_id", "control_name", "framework", "domain",
    "status", "evidence", "owner", "last_reviewed"
]

STATUS_VALUES = ["Implemented", "Partially Implemented", "Not Implemented"]


def load_controls(filepath):
    """Load and validate controls from a CSV file."""
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    controls = []
    with open(filepath, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        missing = [col for col in REQUIRED_COLUMNS if col not in reader.fieldnames]
        if missing:
            print(f"[ERROR] Missing columns: {', '.join(missing)}")
            sys.exit(1)

        for i, row in enumerate(reader, start=2):
            status = row.get("status", "").strip()
            if status not in STATUS_VALUES:
                print(f"[WARNING] Row {i}: Invalid status '{status}' — skipping")
                continue
            controls.append({
                "control_id": row["control_id"].strip(),
                "control_name": row["control_name"].strip(),
                "framework": row["framework"].strip(),
                "domain": row["domain"].strip(),
                "status": status,
                "evidence": row["evidence"].strip(),
                "owner": row["owner"].strip(),
                "last_reviewed": row["last_reviewed"].strip(),
            })

    print(f"[OK] Loaded {len(controls)} controls from {filepath}")
    return controls


# ──────────────────────────────────────────────────
# 2. ANALYSIS ENGINE
# ──────────────────────────────────────────────────

def analyze_compliance(controls):
    """Perform compliance gap analysis and return metrics."""
    total = len(controls)
    status_counts = Counter(c["status"] for c in controls)

    implemented = status_counts.get("Implemented", 0)
    partial = status_counts.get("Partially Implemented", 0)
    not_impl = status_counts.get("Not Implemented", 0)

    score = round(((implemented * 1.0) + (partial * 0.5)) / total * 100, 1) if total else 0

    frameworks = {}
    for c in controls:
        fw = c["framework"]
        if fw not in frameworks:
            frameworks[fw] = {"total": 0, "implemented": 0, "partial": 0, "not_implemented": 0}
        frameworks[fw]["total"] += 1
        if c["status"] == "Implemented":
            frameworks[fw]["implemented"] += 1
        elif c["status"] == "Partially Implemented":
            frameworks[fw]["partial"] += 1
        else:
            frameworks[fw]["not_implemented"] += 1

    for fw in frameworks:
        d = frameworks[fw]
        d["score"] = round(((d["implemented"] * 1.0) + (d["partial"] * 0.5)) / d["total"] * 100, 1)

    domains = {}
    for c in controls:
        dom = c["domain"]
        if dom not in domains:
            domains[dom] = {"total": 0, "implemented": 0, "partial": 0, "not_implemented": 0}
        domains[dom]["total"] += 1
        if c["status"] == "Implemented":
            domains[dom]["implemented"] += 1
        elif c["status"] == "Partially Implemented":
            domains[dom]["partial"] += 1
        else:
            domains[dom]["not_implemented"] += 1

    for dom in domains:
        d = domains[dom]
        d["score"] = round(((d["implemented"] * 1.0) + (d["partial"] * 0.5)) / d["total"] * 100, 1)

    gaps = [c for c in controls if c["status"] != "Implemented"]
    gaps.sort(key=lambda x: (0 if x["status"] == "Not Implemented" else 1, x["framework"]))

    stale = []
    today = datetime.now()
    for c in controls:
        if not c["last_reviewed"]:
            stale.append(c)
        else:
            try:
                reviewed = datetime.strptime(c["last_reviewed"], "%Y-%m-%d")
                if (today - reviewed).days > 90:
                    stale.append(c)
            except ValueError:
                stale.append(c)

    owners = {}
    for c in controls:
        o = c["owner"]
        if o not in owners:
            owners[o] = {"total": 0, "gaps": 0}
        owners[o]["total"] += 1
        if c["status"] != "Implemented":
            owners[o]["gaps"] += 1

    return {
        "total": total,
        "implemented": implemented,
        "partial": partial,
        "not_implemented": not_impl,
        "score": score,
        "frameworks": frameworks,
        "domains": domains,
        "gaps": gaps,
        "stale_reviews": stale,
        "owners": owners,
    }


# ──────────────────────────────────────────────────
# 3. RISK PRIORITIZATION
# ──────────────────────────────────────────────────

DOMAIN_RISK_WEIGHTS = {
    "Technology": 5,
    "Governance": 4,
    "Detect": 4,
    "Respond": 5,
    "Recover": 5,
    "Protect": 4,
    "Identify": 3,
    "People": 3,
    "Physical": 2,
}


def prioritize_gaps(gaps):
    """Assign risk priority scores to each gap."""
    for gap in gaps:
        weight = DOMAIN_RISK_WEIGHTS.get(gap["domain"], 3)
        status_mult = 2 if gap["status"] == "Not Implemented" else 1
        no_evidence = 1.5 if not gap["evidence"] else 1.0
        gap["risk_score"] = round(weight * status_mult * no_evidence, 1)

        if gap["risk_score"] >= 8:
            gap["priority"] = "CRITICAL"
        elif gap["risk_score"] >= 5:
            gap["priority"] = "HIGH"
        elif gap["risk_score"] >= 3:
            gap["priority"] = "MEDIUM"
        else:
            gap["priority"] = "LOW"

    gaps.sort(key=lambda x: x["risk_score"], reverse=True)
    return gaps


# ──────────────────────────────────────────────────
# 4. HTML REPORT GENERATION
# ──────────────────────────────────────────────────

def color_for_score(score):
    if score >= 80:
        return "#22c55e"
    elif score >= 60:
        return "#eab308"
    else:
        return "#ef4444"


def priority_color(priority):
    return {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#16a34a",
    }.get(priority, "#6b7280")


def generate_report(metrics, gaps, output_path):
    """Generate a professional HTML compliance report."""
    now = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    score_color = color_for_score(metrics["score"])

    fw_cards = ""
    for fw, data in metrics["frameworks"].items():
        fc = color_for_score(data["score"])
        fw_cards += f"""
        <div class="card">
            <h3>{fw}</h3>
            <div class="score-circle" style="border-color:{fc}; color:{fc}">{data['score']}%</div>
            <div class="meta">
                <span class="tag green">{data['implemented']} Implemented</span>
                <span class="tag yellow">{data['partial']} Partial</span>
                <span class="tag red">{data['not_implemented']} Gaps</span>
            </div>
        </div>"""

    domain_rows = ""
    for dom, data in sorted(metrics["domains"].items(), key=lambda x: x[1]["score"]):
        dc = color_for_score(data["score"])
        bar_width = data["score"]
        domain_rows += f"""
        <tr>
            <td><strong>{dom}</strong></td>
            <td>{data['total']}</td>
            <td>{data['implemented']}</td>
            <td>{data['partial']}</td>
            <td>{data['not_implemented']}</td>
            <td>
                <div class="bar-container">
                    <div class="bar" style="width:{bar_width}%; background:{dc}"></div>
                </div>
                <span style="color:{dc}; font-weight:600">{data['score']}%</span>
            </td>
        </tr>"""

    gap_rows = ""
    for g in gaps:
        pc = priority_color(g["priority"])
        gap_rows += f"""
        <tr>
            <td><span class="priority-badge" style="background:{pc}">{g['priority']}</span></td>
            <td><code>{g['control_id']}</code></td>
            <td>{g['control_name']}</td>
            <td>{g['framework']}</td>
            <td>{g['domain']}</td>
            <td>{g['status']}</td>
            <td>{g['owner']}</td>
            <td>{g['risk_score']}</td>
        </tr>"""

    owner_rows = ""
    for owner, data in sorted(metrics["owners"].items(), key=lambda x: x[1]["gaps"], reverse=True):
        owner_rows += f"""
        <tr>
            <td><strong>{owner}</strong></td>
            <td>{data['total']}</td>
            <td>{data['gaps']}</td>
            <td>{data['total'] - data['gaps']}</td>
        </tr>"""

    stale_rows = ""
    for c in metrics["stale_reviews"]:
        reviewed = c["last_reviewed"] if c["last_reviewed"] else "Never"
        stale_rows += f"""
        <tr>
            <td><code>{c['control_id']}</code></td>
            <td>{c['control_name']}</td>
            <td>{reviewed}</td>
            <td>{c['owner']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GRC Compliance Gap Analysis Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #f1f5f9; color: #1e293b; line-height: 1.6; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
    header {{ background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%); color: white; padding: 40px 0; text-align: center; }}
    header h1 {{ font-size: 28px; font-weight: 700; }}
    header p {{ opacity: 0.85; margin-top: 8px; font-size: 14px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0; }}
    .card {{ background: white; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); text-align: center; }}
    .card h3 {{ font-size: 14px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }}
    .big-number {{ font-size: 48px; font-weight: 700; }}
    .score-circle {{ font-size: 36px; font-weight: 700; border: 4px solid; border-radius: 50%; width: 80px; height: 80px; display: flex; align-items: center; justify-content: center; margin: 8px auto; }}
    .meta {{ margin-top: 12px; display: flex; gap: 6px; justify-content: center; flex-wrap: wrap; }}
    .tag {{ font-size: 11px; padding: 2px 8px; border-radius: 99px; font-weight: 600; }}
    .tag.green {{ background: #dcfce7; color: #166534; }}
    .tag.yellow {{ background: #fef9c3; color: #854d0e; }}
    .tag.red {{ background: #fee2e2; color: #991b1b; }}
    section {{ margin: 32px 0; }}
    section h2 {{ font-size: 20px; font-weight: 700; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    th {{ background: #f8fafc; padding: 12px 16px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; border-bottom: 2px solid #e2e8f0; }}
    td {{ padding: 10px 16px; border-bottom: 1px solid #f1f5f9; font-size: 13px; }}
    tr:hover {{ background: #f8fafc; }}
    code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
    .priority-badge {{ color: white; padding: 3px 10px; border-radius: 99px; font-size: 11px; font-weight: 700; }}
    .bar-container {{ width: 100px; height: 8px; background: #e2e8f0; border-radius: 4px; display: inline-block; vertical-align: middle; margin-right: 8px; }}
    .bar {{ height: 100%; border-radius: 4px; }}
    footer {{ text-align: center; padding: 32px 0; color: #94a3b8; font-size: 12px; }}
</style>
</head>
<body>

<header>
    <h1>GRC Compliance Gap Analysis Report</h1>
    <p>Generated on {now} | Braelyn Jones — GRC Compliance Analyzer</p>
</header>

<div class="container">

    <div class="summary-grid">
        <div class="card">
            <h3>Overall Compliance Score</h3>
            <div class="big-number" style="color:{score_color}">{metrics['score']}%</div>
        </div>
        <div class="card">
            <h3>Total Controls</h3>
            <div class="big-number">{metrics['total']}</div>
        </div>
        <div class="card">
            <h3>Implemented</h3>
            <div class="big-number" style="color:#22c55e">{metrics['implemented']}</div>
        </div>
        <div class="card">
            <h3>Gaps Found</h3>
            <div class="big-number" style="color:#ef4444">{metrics['not_implemented'] + metrics['partial']}</div>
        </div>
    </div>

    <section>
        <h2>Framework Compliance Breakdown</h2>
        <div class="summary-grid">{fw_cards}</div>
    </section>

    <section>
        <h2>Compliance by Domain</h2>
        <table>
            <thead><tr><th>Domain</th><th>Total</th><th>Implemented</th><th>Partial</th><th>Gaps</th><th>Score</th></tr></thead>
            <tbody>{domain_rows}</tbody>
        </table>
    </section>

    <section>
        <h2>Prioritized Gap Remediation</h2>
        <table>
            <thead><tr><th>Priority</th><th>Control ID</th><th>Control</th><th>Framework</th><th>Domain</th><th>Status</th><th>Owner</th><th>Risk Score</th></tr></thead>
            <tbody>{gap_rows}</tbody>
        </table>
    </section>

    <section>
        <h2>Control Ownership Summary</h2>
        <table>
            <thead><tr><th>Owner</th><th>Total Controls</th><th>Open Gaps</th><th>Compliant</th></tr></thead>
            <tbody>{owner_rows}</tbody>
        </table>
    </section>

    <section>
        <h2>Stale / Missing Reviews (>90 Days)</h2>
        <table>
            <thead><tr><th>Control ID</th><th>Control</th><th>Last Reviewed</th><th>Owner</th></tr></thead>
            <tbody>{stale_rows}</tbody>
        </table>
    </section>

</div>

<footer>
    <p>GRC Compliance Gap Analyzer &mdash; Built by Braelyn Jones | github.com/braelyn225</p>
</footer>

</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[OK] Report saved to {output_path}")


# ──────────────────────────────────────────────────
# 5. TERMINAL SUMMARY
# ──────────────────────────────────────────────────

def print_summary(metrics, gaps):
    """Print a quick summary to the terminal."""
    print("\n" + "=" * 60)
    print("  GRC COMPLIANCE GAP ANALYSIS — SUMMARY")
    print("=" * 60)
    print(f"  Overall Compliance Score:  {metrics['score']}%")
    print(f"  Total Controls Assessed:   {metrics['total']}")
    print(f"  Implemented:               {metrics['implemented']}")
    print(f"  Partially Implemented:     {metrics['partial']}")
    print(f"  Not Implemented:           {metrics['not_implemented']}")
    print("-" * 60)

    print("\n  FRAMEWORK SCORES:")
    for fw, data in metrics["frameworks"].items():
        print(f"    {fw:20s}  {data['score']}%  ({data['implemented']}/{data['total']} fully implemented)")

    print(f"\n  TOP 5 CRITICAL GAPS:")
    for g in gaps[:5]:
        print(f"    [{g['priority']:8s}] {g['control_id']:10s} {g['control_name'][:40]:40s} (Score: {g['risk_score']})")

    print(f"\n  STALE REVIEWS: {len(metrics['stale_reviews'])} controls need review")
    print("=" * 60 + "\n")


# ──────────────────────────────────────────────────
# 6. MAIN
# ──────────────────────────────────────────────────

def main():
    input_file = "sample_controls.csv"
    output_file = "compliance_report.html"

    if len(sys.argv) >= 2:
        input_file = sys.argv[1]
    if len(sys.argv) >= 3:
        output_file = sys.argv[2]

    print("\n🔍 GRC Compliance Gap Analyzer")
    print(f"   Input:  {input_file}")
    print(f"   Output: {output_file}\n")

    controls = load_controls(input_file)
    metrics = analyze_compliance(controls)
    gaps = prioritize_gaps(metrics["gaps"])
    print_summary(metrics, gaps)
    generate_report(metrics, gaps, output_file)
    print("✅ Analysis complete. Open the HTML report in your browser.\n")


if __name__ == "__main__":
    main()
```

