#!/usr/bin/env python3
"""
YARA Scanner for npm-binary-scanner

Scans binary files using YARA rules and outputs results in JSON format.
Can use bundled rules and/or user-provided rules.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

try:
    import yara
except ImportError:
    print("Error: yara-python is not installed. Run: pip install yara-python", file=sys.stderr)
    sys.exit(1)


def load_rules(rules_paths: list[str]) -> Optional[yara.Rules]:
    """
    Load and compile YARA rules from multiple paths.
    
    Args:
        rules_paths: List of paths to .yar files or directories containing them
        
    Returns:
        Compiled YARA rules object or None if no rules found
    """
    rule_files = {}
    
    for path in rules_paths:
        path = Path(path)
        if not path.exists():
            print(f"Warning: Rules path does not exist: {path}", file=sys.stderr)
            continue
            
        if path.is_file() and path.suffix in ('.yar', '.yara'):
            namespace = path.stem
            rule_files[namespace] = str(path)
        elif path.is_dir():
            for rule_file in path.glob('*.yar'):
                namespace = rule_file.stem
                rule_files[namespace] = str(rule_file)
            for rule_file in path.glob('*.yara'):
                namespace = rule_file.stem
                rule_files[namespace] = str(rule_file)
    
    if not rule_files:
        print("Warning: No YARA rules found", file=sys.stderr)
        return None
    
    print(f"Loading {len(rule_files)} rule file(s):", file=sys.stderr)
    for namespace, path in rule_files.items():
        print(f"  - {namespace}: {path}", file=sys.stderr)
    
    try:
        rules = yara.compile(filepaths=rule_files)
        return rules
    except yara.SyntaxError as e:
        print(f"Error compiling YARA rules: {e}", file=sys.stderr)
        sys.exit(1)


def scan_file(rules: yara.Rules, file_path: str, timeout: int = 60) -> list[dict]:
    """
    Scan a single file with YARA rules.
    
    Args:
        rules: Compiled YARA rules
        file_path: Path to file to scan
        timeout: Scan timeout in seconds
        
    Returns:
        List of match dictionaries
    """
    matches = []
    
    try:
        results = rules.match(file_path, timeout=timeout)
        for match in results:
            match_data = {
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': list(match.tags) if match.tags else [],
                'meta': dict(match.meta) if match.meta else {},
                'strings': []
            }
            
            # Extract matched strings (limit to first 10 to avoid huge output)
            for string_match in match.strings[:10]:
                match_data['strings'].append({
                    'identifier': string_match.identifier,
                    'offset': string_match.instances[0].offset if string_match.instances else 0,
                })
            
            matches.append(match_data)
            
    except yara.TimeoutError:
        print(f"Warning: Scan timeout for {file_path}", file=sys.stderr)
    except yara.Error as e:
        print(f"Warning: YARA error scanning {file_path}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Error scanning {file_path}: {e}", file=sys.stderr)
    
    return matches


def scan_files_from_json(rules: yara.Rules, json_path: str, timeout: int = 60) -> dict:
    """
    Scan files listed in binary-scan-results.json.
    
    Args:
        rules: Compiled YARA rules
        json_path: Path to binary-scan-results.json
        timeout: Scan timeout per file
        
    Returns:
        Dictionary with scan results
    """
    with open(json_path, 'r') as f:
        scan_results = json.load(f)
    
    base_path = Path(json_path).parent
    node_modules = base_path / 'node_modules'
    
    yara_results = {
        'totalScanned': 0,
        'totalMatches': 0,
        'filesWithMatches': 0,
        'results': []
    }
    
    packages = scan_results.get('packages', [])
    total_files = sum(len(pkg.get('executables', [])) for pkg in packages)
    
    print(f"\nScanning {total_files} files with YARA...", file=sys.stderr)
    
    scanned = 0
    for package in packages:
        for executable in package.get('executables', []):
            file_path = executable.get('path', '')
            
            # Construct full path
            if file_path.startswith('node_modules/'):
                full_path = base_path / file_path
            else:
                full_path = node_modules / file_path
            
            if not full_path.exists():
                print(f"Warning: File not found: {full_path}", file=sys.stderr)
                continue
            
            scanned += 1
            if scanned % 10 == 0 or scanned == total_files:
                print(f"  Progress: {scanned}/{total_files}", file=sys.stderr)
            
            matches = scan_file(rules, str(full_path), timeout)
            
            yara_results['totalScanned'] += 1
            
            if matches:
                yara_results['totalMatches'] += len(matches)
                yara_results['filesWithMatches'] += 1
                
                result = {
                    'file': file_path,
                    'package': package.get('name', 'unknown'),
                    'version': package.get('version', 'unknown'),
                    'sha256': executable.get('sha256', ''),
                    'matches': matches
                }
                yara_results['results'].append(result)
                
                # Print matches as we find them
                for match in matches:
                    severity = match.get('meta', {}).get('severity', 'unknown')
                    print(f"  [!] {file_path}: {match['rule']} (severity: {severity})", file=sys.stderr)
    
    return yara_results


def scan_directory(rules: yara.Rules, directory: str, timeout: int = 60) -> dict:
    """
    Scan all files in a directory recursively.
    
    Args:
        rules: Compiled YARA rules
        directory: Directory to scan
        timeout: Scan timeout per file
        
    Returns:
        Dictionary with scan results
    """
    yara_results = {
        'totalScanned': 0,
        'totalMatches': 0,
        'filesWithMatches': 0,
        'results': []
    }
    
    dir_path = Path(directory)
    files = list(dir_path.rglob('*'))
    files = [f for f in files if f.is_file()]
    
    print(f"\nScanning {len(files)} files with YARA...", file=sys.stderr)
    
    for i, file_path in enumerate(files):
        if (i + 1) % 10 == 0 or (i + 1) == len(files):
            print(f"  Progress: {i + 1}/{len(files)}", file=sys.stderr)
        
        matches = scan_file(rules, str(file_path), timeout)
        
        yara_results['totalScanned'] += 1
        
        if matches:
            yara_results['totalMatches'] += len(matches)
            yara_results['filesWithMatches'] += 1
            
            result = {
                'file': str(file_path.relative_to(dir_path)),
                'matches': matches
            }
            yara_results['results'].append(result)
            
            for match in matches:
                severity = match.get('meta', {}).get('severity', 'unknown')
                print(f"  [!] {file_path}: {match['rule']} (severity: {severity})", file=sys.stderr)
    
    return yara_results


def emit_github_annotations(results: dict) -> int:
    """
    Emit GitHub Actions annotations for YARA matches.
    
    Args:
        results: YARA scan results
        
    Returns:
        Count of high severity matches
    """
    high_severity_count = 0
    
    for result in results.get('results', []):
        file_path = result.get('file', 'unknown')
        package = result.get('package', '')
        
        for match in result.get('matches', []):
            rule = match.get('rule', 'unknown')
            severity = match.get('meta', {}).get('severity', 'unknown')
            description = match.get('meta', {}).get('description', '')
            category = match.get('meta', {}).get('category', '')
            
            message = f"{file_path}"
            if package:
                message = f"{package}: {file_path}"
            message += f" - {rule}"
            if description:
                message += f" ({description})"
            
            if severity == 'critical' or severity == 'high':
                print(f"::error title=YARA {severity.upper()} - {category}::{message}")
                high_severity_count += 1
            elif severity == 'medium':
                print(f"::warning title=YARA {severity.upper()} - {category}::{message}")
            else:
                print(f"::notice title=YARA {severity.upper()} - {category}::{message}")
    
    return high_severity_count


def main():
    parser = argparse.ArgumentParser(
        description='Scan files with YARA rules',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan using binary-scan-results.json
  python yara_scanner.py --input results.json --rules ./rules

  # Scan a directory directly
  python yara_scanner.py --dir ./node_modules --rules ./rules

  # Use multiple rule sources
  python yara_scanner.py --input results.json --rules ./rules --rules ./custom-rules

  # Output to file
  python yara_scanner.py --input results.json --rules ./rules --output yara-results.json
'''
    )
    
    parser.add_argument(
        '--input', '-i',
        help='Path to binary-scan-results.json from npm-binary-scanner'
    )
    parser.add_argument(
        '--dir', '-d',
        help='Directory to scan directly (alternative to --input)'
    )
    parser.add_argument(
        '--rules', '-r',
        action='append',
        default=[],
        help='Path to YARA rules file or directory (can be specified multiple times)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file for JSON results (default: stdout)'
    )
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=60,
        help='Scan timeout per file in seconds (default: 60)'
    )
    parser.add_argument(
        '--github-annotations',
        action='store_true',
        help='Emit GitHub Actions annotations'
    )
    parser.add_argument(
        '--bundled-rules',
        action='store_true',
        default=True,
        help='Include bundled rules from ./rules directory (default: true)'
    )
    parser.add_argument(
        '--no-bundled-rules',
        action='store_true',
        help='Exclude bundled rules'
    )
    
    args = parser.parse_args()
    
    if not args.input and not args.dir:
        parser.error('Either --input or --dir must be specified')
    
    # Collect rule paths
    rules_paths = list(args.rules)
    
    # Add bundled rules unless explicitly disabled
    if not args.no_bundled_rules:
        script_dir = Path(__file__).parent
        bundled_rules = script_dir / 'rules'
        if bundled_rules.exists():
            rules_paths.insert(0, str(bundled_rules))
    
    if not rules_paths:
        print("Error: No YARA rules specified", file=sys.stderr)
        sys.exit(1)
    
    # Load rules
    rules = load_rules(rules_paths)
    if not rules:
        print("Error: Failed to load YARA rules", file=sys.stderr)
        sys.exit(1)
    
    # Scan
    if args.input:
        results = scan_files_from_json(rules, args.input, args.timeout)
    else:
        results = scan_directory(rules, args.dir, args.timeout)
    
    # Summary
    print(f"\n=== YARA Scan Summary ===", file=sys.stderr)
    print(f"Files scanned: {results['totalScanned']}", file=sys.stderr)
    print(f"Files with matches: {results['filesWithMatches']}", file=sys.stderr)
    print(f"Total matches: {results['totalMatches']}", file=sys.stderr)
    
    # GitHub annotations
    if args.github_annotations:
        high_count = emit_github_annotations(results)
        print(f"\nyara-matches={results['filesWithMatches']}", file=sys.stderr)
        print(f"yara-high-severity={high_count}", file=sys.stderr)
    
    # Output
    output_json = json.dumps(results, indent=2)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_json)
        print(f"\nResults written to: {args.output}", file=sys.stderr)
    else:
        print(output_json)
    
    # Exit with error if high severity matches found
    if results['filesWithMatches'] > 0:
        sys.exit(0)  # Don't fail, let the action decide based on outputs
    
    sys.exit(0)


if __name__ == '__main__':
    main()

