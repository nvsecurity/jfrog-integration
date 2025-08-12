import json
import re
import sys
from os import path


def parse_sarif_file(sarif_data: dict[str]) -> dict[str]:
    """Parse SARIF file and extract relevant information"""

    # Extract tool information
    tool_info = sarif_data["runs"][0]["tool"]["driver"]
    tool_name = tool_info.get("name", "Unknown")
    tool_version = tool_info.get("version", "Unknown")
    scan_url = tool_info.get("informationUri", "")

    # Extract rules
    rules = {}
    for rule in tool_info.get("rules", []):
        rules[rule["id"]] = {
            "name": rule.get("name", ""),
            "description": rule.get("fullDescription", {}).get("text", ""),
            "short_description": rule.get("shortDescription", {}).get("text", ""),
        }

    # Extract results
    results = []
    for result in sarif_data["runs"][0].get("results", []):
        rule_id = result.get("ruleId", "")
        rule_info = rules.get(rule_id, {})
        result_data = _convert_result(result, rule_info)
        results.append(result_data)

    return {
        "tool_name": tool_name,
        "tool_version": tool_version,
        "scan_url": scan_url,
        "results": results,
    }


def _convert_result(result, rule_info: dict) -> dict:
    """Convert a SARIF result to a simplified dictionary format"""

    rule_description = rule_info.get("description", "")

    # Extract basic information
    vulnerability_name = result.get("message", {}).get("text", "")
    properties = result.get("properties", {})

    # Extract endpoint information
    endpoint = properties.get("path", "")
    if not endpoint or endpoint == "-":
        url = properties.get("url", "")
        endpoint = __extract_endpoint_from_url(url)
    if not endpoint or endpoint == "-":
        endpoint = __extract_endpoint_from_description(rule_description)

    method = __extract_method_from_description(rule_description)

    # Extract location information
    file_location = "-"
    locations = result.get("locations", [])
    if locations and "physicalLocation" in locations[0]:
        phys_loc = locations[0]["physicalLocation"]
        if "artifactLocation" in phys_loc:
            file_path = phys_loc["artifactLocation"].get("uri", "")
            if "region" in phys_loc and "startLine" in phys_loc["region"]:
                line_num = phys_loc["region"]["startLine"]
                file_location = f"{file_path}:{line_num}" if file_path != "-" else "-"
            elif file_path:
                file_location = file_path

    result_data = {
        "vulnerability": vulnerability_name,
        "risk": properties.get("nightvision-risk", "-"),
        "confidence": properties.get("nightvision-confidence", "-"),
        "security_severity": properties.get("security-severity", "-"),
        "endpoint": endpoint,
        "method": method,
        "parameter": (
            ", ".join(properties.get("parameter", []))
            if properties.get("parameter")
            else "-"
        ),
        "payload": properties.get("payload", "-"),
        "file_location": file_location,
        "issue_id": result.get("partialFingerprints", {}).get(
            "nightvisionIssueID/v1", ""
        ),
    }
    return result_data


def __extract_endpoint_from_url(url: str) -> str:
    """Extract endpoint path from URL"""

    if not url or url == "-":
        return "-"
    # Extract path component from URL
    path_match = re.search(r"(?:https?://[^/]+)?(/[^\s?#]*)", url)
    return path_match.group(1) if path_match else "-"


def __extract_endpoint_from_description(description: str) -> str:
    """Extract endpoint path from vulnerability description"""

    # Look for patterns like "The `/path/` URL path is vulnerable"
    pattern = r"The `([^`]+)` URL path is vulnerable"
    match = re.search(pattern, description)
    if match:
        return match.group(1)
    return "-"


def __extract_method_from_description(description: str) -> str:
    """Extract HTTP method from vulnerability description"""

    # Look for patterns like "via a METHOD request."
    pattern = r"via a (\S+) request"
    match = re.search(pattern, description)
    if match:
        return match.group(1).upper()
    return "-"


def generate_markdown_report(parsed_data: dict[str]) -> str:
    """Generate Markdown report from parsed SARIF data"""

    tool_name = parsed_data["tool_name"]
    tool_version = parsed_data["tool_version"]
    scan_url = parsed_data["scan_url"]
    results = parsed_data["results"]

    # Start building the markdown
    markdown = f"""# Security Vulnerability Report

**Tool:** {tool_name} v{tool_version}

**Scan URL:** {scan_url}

## Vulnerability Findings

| Vulnerability | Risk | Confidence | Endpoint | Method | Parameter | Payload | File Location |
|---------------|------|------------|----------|--------|-----------|---------|---------------|
"""

    # Add each vulnerability as a table row
    for result in results:
        payload = result["payload"]
        # Escape pipe characters and backticks in payload for markdown table
        if payload != "-":
            payload = f"`{payload}`"

        markdown += f"| {result['vulnerability']} | {result['risk']} | {result['confidence']} | {result['endpoint']} | {result['method']} | {result['parameter']} | {payload} | {result['file_location']} |\n"

    # Generate summary statistics
    risk_counts = {}
    for result in results:
        risk = result["risk"]
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    markdown += f"""
## Summary Statistics

| Risk Level | Count |
|------------|-------|
"""

    for risk, count in sorted(risk_counts.items()):
        markdown += f"| {risk} | {count} |\n"

    # Generate endpoint summary
    endpoint_stats = {}
    for result in results:
        endpoint = result["endpoint"]
        if endpoint not in endpoint_stats:
            endpoint_stats[endpoint] = {"count": 0, "highest_risk": "-"}
        endpoint_stats[endpoint]["count"] += 1

        # Determine highest risk (simple priority: CRITICAL > HIGH > MEDIUM > LOW)
        current_risk = result["risk"]
        current_highest = endpoint_stats[endpoint]["highest_risk"]

        risk_priority = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "-": 0}
        if risk_priority.get(current_risk, 0) > risk_priority.get(current_highest, 0):
            endpoint_stats[endpoint]["highest_risk"] = current_risk

    markdown += f"""
## Affected Endpoints Summary

| Endpoint | Vulnerability Count | Highest Risk |
|----------|-------------------|--------------|
"""

    for endpoint, stats in sorted(endpoint_stats.items()):
        markdown += f"| {endpoint} | {stats['count']} | {stats['highest_risk']} |\n"

    # Generate file location summary
    file_stats = {}
    for result in results:
        file_loc = result["file_location"]
        if file_loc != "-" and ":" in file_loc:
            file_path, line = file_loc.split(":", 1)
            if file_path not in file_stats:
                file_stats[file_path] = {}
            if line not in file_stats[file_path]:
                file_stats[file_path][line] = 0
            file_stats[file_path][line] += 1

    if file_stats:
        markdown += f"""
## File Locations Summary

| File | Line | Vulnerability Count |
|------|------|-------------------|
"""

        for file_path, lines in sorted(file_stats.items()):
            for line, count in sorted(lines.items()):
                markdown += f"| {file_path} | {line} | {count} |\n"

    return markdown


if __name__ == "__main__":
    if len(sys.argv) != 3:
        script_name = path.basename(__file__)
        print(f"Usage: python {script_name} <input_sarif_file> <output_markdown_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            sarif_data = json.load(f)

        parsed_data = parse_sarif_file(sarif_data)
        markdown_report = generate_markdown_report(parsed_data)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(markdown_report)

        print(f"Successfully converted {input_file} to {output_file}")
        print(f"Found {len(parsed_data['results'])} vulnerabilities")

    except FileNotFoundError:
        print(f"Error: Could not find input file '{input_file}'")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in SARIF file - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
