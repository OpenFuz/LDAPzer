"""
Results Logger

Handles logging, storage, and reporting of test results.
Supports multiple output formats: JSON, CSV, HTML, Markdown.
"""

import json
import csv
import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


class ResultsLogger:
    """
    Log and format test results

    Supports multiple output formats and provides summary statistics
    """

    def __init__(self, output_file: Optional[str] = None):
        """
        Initialize results logger

        Args:
            output_file: Output file path (optional)
        """
        self.output_file = output_file
        self.results: List[Dict] = []
        self.metadata = {
            'timestamp': datetime.datetime.now().isoformat(),
            'test_plan': 'RFC 4511 - Test Cases 1.1.1, 1.1.2, 1.1.3',
            'version': '1.0.0'
        }

    def add_metadata(self, key: str, value: Any):
        """Add metadata field"""
        self.metadata[key] = value

    def log_socket_results(self, results: List) -> None:
        """
        Log results from socket-based fuzzer

        Args:
            results: List of FuzzResult objects
        """
        for result in results:
            self.results.append(result.to_dict())

    def log_scapy_results(self, results: List) -> None:
        """
        Log results from Scapy-based test sender

        Args:
            results: List of TestResult objects
        """
        for result in results:
            self.results.append({
                'test_id': result.test_id,
                'test_name': result.test_name,
                'packet_sent_hex': result.packet_sent.hex(),
                'packet_sent_len': len(result.packet_sent),
                'response_received_hex': result.response_received.hex() if result.response_received else None,
                'response_received_len': len(result.response_received) if result.response_received else 0,
                'server_status': result.analysis.value,
                'result_code': result.result_code,
                'response_time_ms': round(result.response_time * 1000, 2),
                'error_message': result.notes,
                'timestamp': result.response_time
            })

    def log_dict_results(self, results: List[Dict]) -> None:
        """
        Log results from dictionaries

        Args:
            results: List of result dictionaries
        """
        self.results.extend(results)

    def get_summary_statistics(self) -> Dict:
        """
        Calculate summary statistics

        Returns:
            Dictionary of summary statistics
        """
        if not self.results:
            return {}

        total = len(self.results)

        # Count by status
        status_counts = {}
        result_code_counts = {}

        for result in self.results:
            status = result.get('server_status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1

            rc = result.get('result_code')
            if rc is not None:
                result_code_counts[rc] = result_code_counts.get(rc, 0) + 1

        # Response times
        response_times = [r.get('response_time_ms', 0) for r in self.results
                         if r.get('response_time_ms') is not None]

        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        min_response_time = min(response_times) if response_times else 0
        max_response_time = max(response_times) if response_times else 0

        return {
            'total_tests': total,
            'status_counts': status_counts,
            'result_code_counts': result_code_counts,
            'response_time_stats': {
                'average_ms': round(avg_response_time, 2),
                'min_ms': round(min_response_time, 2),
                'max_ms': round(max_response_time, 2)
            }
        }

    def to_json(self, pretty: bool = True) -> str:
        """
        Convert results to JSON

        Args:
            pretty: Pretty-print JSON

        Returns:
            JSON string
        """
        data = {
            'metadata': self.metadata,
            'summary': self.get_summary_statistics(),
            'results': self.results
        }

        if pretty:
            return json.dumps(data, indent=2)
        else:
            return json.dumps(data)

    def to_csv(self) -> str:
        """
        Convert results to CSV

        Returns:
            CSV string
        """
        if not self.results:
            return ""

        import io
        output = io.StringIO()

        # Get all keys from first result
        fieldnames = list(self.results[0].keys())

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for result in self.results:
            writer.writerow(result)

        return output.getvalue()

    def to_markdown(self) -> str:
        """
        Convert results to Markdown report

        Returns:
            Markdown string
        """
        md = []

        # Header
        md.append("# LDAP Protocol Security Assessment Results")
        md.append("")
        md.append(f"**Test Plan:** {self.metadata['test_plan']}")
        md.append(f"**Timestamp:** {self.metadata['timestamp']}")
        md.append("")

        # Summary
        summary = self.get_summary_statistics()
        md.append("## Summary Statistics")
        md.append("")
        md.append(f"- **Total Tests:** {summary.get('total_tests', 0)}")
        md.append("")

        # Status counts
        md.append("### Test Results by Status")
        md.append("")
        status_counts = summary.get('status_counts', {})
        for status, count in sorted(status_counts.items()):
            md.append(f"- **{status}:** {count}")
        md.append("")

        # Result codes
        if summary.get('result_code_counts'):
            md.append("### LDAP Result Codes Received")
            md.append("")
            rc_counts = summary.get('result_code_counts', {})
            for rc, count in sorted(rc_counts.items()):
                rc_name = self._get_result_code_name(rc)
                md.append(f"- **{rc}** ({rc_name}): {count}")
            md.append("")

        # Response times
        rt_stats = summary.get('response_time_stats', {})
        if rt_stats:
            md.append("### Response Time Statistics")
            md.append("")
            md.append(f"- **Average:** {rt_stats.get('average_ms', 0)} ms")
            md.append(f"- **Minimum:** {rt_stats.get('min_ms', 0)} ms")
            md.append(f"- **Maximum:** {rt_stats.get('max_ms', 0)} ms")
            md.append("")

        # Detailed results table
        md.append("## Detailed Test Results")
        md.append("")
        md.append("| Test ID | Test Name | Status | Result Code | Response Time (ms) |")
        md.append("|---------|-----------|--------|-------------|-------------------|")

        for result in self.results:
            test_id = result.get('test_id', 'N/A')
            test_name = result.get('test_name', 'N/A')
            status = result.get('server_status', 'N/A')
            result_code = result.get('result_code', 'N/A')
            response_time = result.get('response_time_ms', 'N/A')

            md.append(f"| {test_id} | {test_name} | {status} | {result_code} | {response_time} |")

        md.append("")

        # Findings
        md.append("## Key Findings")
        md.append("")
        md.append(self._generate_findings(summary))
        md.append("")

        return "\n".join(md)

    def to_html(self) -> str:
        """
        Convert results to HTML report

        Returns:
            HTML string
        """
        summary = self.get_summary_statistics()

        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        html.append("<head>")
        html.append("<title>LDAP Protocol Security Assessment Results</title>")
        html.append("<style>")
        html.append("body { font-family: Arial, sans-serif; margin: 20px; }")
        html.append("h1 { color: #333; }")
        html.append("h2 { color: #666; border-bottom: 2px solid #ddd; }")
        html.append("table { border-collapse: collapse; width: 100%; margin: 20px 0; }")
        html.append("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
        html.append("th { background-color: #4CAF50; color: white; }")
        html.append("tr:nth-child(even) { background-color: #f2f2f2; }")
        html.append(".summary { background-color: #f9f9f9; padding: 15px; border-radius: 5px; }")
        html.append(".error { color: red; }")
        html.append(".success { color: green; }")
        html.append("</style>")
        html.append("</head>")
        html.append("<body>")

        # Header
        html.append("<h1>LDAP Protocol Security Assessment Results</h1>")
        html.append(f"<p><strong>Test Plan:</strong> {self.metadata['test_plan']}</p>")
        html.append(f"<p><strong>Timestamp:</strong> {self.metadata['timestamp']}</p>")

        # Summary
        html.append("<div class='summary'>")
        html.append("<h2>Summary Statistics</h2>")
        html.append(f"<p><strong>Total Tests:</strong> {summary.get('total_tests', 0)}</p>")

        html.append("<h3>Status Counts</h3>")
        html.append("<ul>")
        for status, count in sorted(summary.get('status_counts', {}).items()):
            html.append(f"<li><strong>{status}:</strong> {count}</li>")
        html.append("</ul>")
        html.append("</div>")

        # Detailed results table
        html.append("<h2>Detailed Test Results</h2>")
        html.append("<table>")
        html.append("<tr>")
        html.append("<th>Test ID</th><th>Test Name</th><th>Status</th>")
        html.append("<th>Result Code</th><th>Response Time (ms)</th>")
        html.append("</tr>")

        for result in self.results:
            html.append("<tr>")
            html.append(f"<td>{result.get('test_id', 'N/A')}</td>")
            html.append(f"<td>{result.get('test_name', 'N/A')}</td>")
            html.append(f"<td>{result.get('server_status', 'N/A')}</td>")
            html.append(f"<td>{result.get('result_code', 'N/A')}</td>")
            html.append(f"<td>{result.get('response_time_ms', 'N/A')}</td>")
            html.append("</tr>")

        html.append("</table>")
        html.append("</body>")
        html.append("</html>")

        return "\n".join(html)

    def save(self, output_file: Optional[str] = None, format: str = 'json') -> None:
        """
        Save results to file

        Args:
            output_file: Output file path (overrides init value)
            format: Output format ('json', 'csv', 'markdown', 'html')
        """
        file_path = output_file or self.output_file

        if not file_path:
            raise ValueError("No output file specified")

        # Determine format from extension if not specified
        if format == 'json' or file_path.endswith('.json'):
            content = self.to_json()
        elif format == 'csv' or file_path.endswith('.csv'):
            content = self.to_csv()
        elif format == 'markdown' or file_path.endswith('.md'):
            content = self.to_markdown()
        elif format == 'html' or file_path.endswith('.html'):
            content = self.to_html()
        else:
            # Default to JSON
            content = self.to_json()

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def print_summary(self) -> None:
        """Print summary to console"""
        summary = self.get_summary_statistics()

        print("\n" + "="*70)
        print("TEST RESULTS SUMMARY")
        print("="*70)
        print(f"\nTotal Tests: {summary.get('total_tests', 0)}")

        print("\nStatus Counts:")
        for status, count in sorted(summary.get('status_counts', {}).items()):
            print(f"  {status}: {count}")

        if summary.get('result_code_counts'):
            print("\nResult Code Counts:")
            for rc, count in sorted(summary.get('result_code_counts', {}).items()):
                rc_name = self._get_result_code_name(rc)
                print(f"  {rc} ({rc_name}): {count}")

        rt_stats = summary.get('response_time_stats', {})
        if rt_stats:
            print("\nResponse Time Statistics:")
            print(f"  Average: {rt_stats.get('average_ms', 0)} ms")
            print(f"  Min: {rt_stats.get('min_ms', 0)} ms")
            print(f"  Max: {rt_stats.get('max_ms', 0)} ms")

        print("\n" + "="*70 + "\n")

    @staticmethod
    def _get_result_code_name(code: int) -> str:
        """Get LDAP result code name"""
        codes = {
            0: "success",
            1: "operationsError",
            2: "protocolError",
            3: "timeLimitExceeded",
            4: "sizeLimitExceeded",
            7: "authMethodNotSupported",
            8: "strongerAuthRequired",
            10: "referral",
            14: "saslBindInProgress",
            51: "busy",
            52: "unavailable"
        }
        return codes.get(code, "unknown")

    def _generate_findings(self, summary: Dict) -> str:
        """Generate key findings text"""
        findings = []

        status_counts = summary.get('status_counts', {})
        total = summary.get('total_tests', 0)

        # Protocol errors
        protocol_errors = status_counts.get('protocol_error', 0)
        if protocol_errors > 0:
            findings.append(f"- **{protocol_errors}/{total}** tests triggered protocol errors (expected behavior for malformed inputs)")

        # Connection issues
        closed = status_counts.get('connection_closed', 0)
        refused = status_counts.get('connection_refused', 0)
        if closed > 0 or refused > 0:
            findings.append(f"- **{closed + refused}/{total}** tests caused connection issues (potential crash/hang)")

        # Timeouts
        timeouts = status_counts.get('timeout', 0)
        if timeouts > 0:
            findings.append(f"- **{timeouts}/{total}** tests timed out (possible DoS or hang condition)")

        # Successful responses
        success = status_counts.get('responsive', 0) or status_counts.get('valid_response', 0)
        if success > 0:
            findings.append(f"- **{success}/{total}** tests received valid responses (server may accept malformed input)")

        if not findings:
            findings.append("- No significant findings")

        return "\n".join(findings)


# CLI for standalone use
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Convert test results to different formats')
    parser.add_argument('input_file', help='Input JSON file with results')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'markdown', 'html'],
                       default='json', help='Output format')

    args = parser.parse_args()

    # Load results
    with open(args.input_file, 'r') as f:
        data = json.load(f)

    logger = ResultsLogger()
    logger.metadata = data.get('metadata', {})
    logger.results = data.get('results', [])

    # Print summary
    logger.print_summary()

    # Save if output specified
    if args.output:
        logger.save(args.output, args.format)
        print(f"Results saved to {args.output}")
