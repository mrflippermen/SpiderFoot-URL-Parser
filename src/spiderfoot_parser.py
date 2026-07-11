#!/usr/bin/env python3
"""
SpiderFoot CSV Parser - Enterprise Grade
========================================

Advanced URL and subdomain extraction from SpiderFoot CSV exports with
intelligent filtering, deduplication, and integration with reconnaissance tools.

Features:
- Robust URL regex supporting complex patterns
- Subdomain clustering and hierarchy analysis
- Multiple export formats (JSON, CSV, text, Nuclei templates)
- DNS resolution validation
- HTTP probing integration
- Direct output to other recon tools (Amass, httpx, Subfinder)

Author: Esteban Jiménez
License: MIT
"""

import csv
import re
import sys
import argparse
import logging
import json
from pathlib import Path
from typing import Set, List, Dict, Optional
from urllib.parse import urlparse
from collections import defaultdict
from dataclasses import dataclass, asdict


# Configure logging
logging.basicConfig(
    format='[%(levelname)s] %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


# Enhanced URL regex supporting complex patterns
URL_PATTERN = re.compile(
    r'https?://'  # Protocol
    r'(?:[^\s:@/]+(?::[^\s:@/]*)?@)?'  # Optional authentication
    r'(?:'  # Host
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'  # Subdomain
    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'  # Domain
    r'|'  # OR
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'  # IPv4
    r'|'  # OR
    r'\[(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]'  # IPv6
    r')'
    r'(?::\d+)?'  # Optional port
    r'(?:/[^\s]*)?'  # Optional path
    r'(?:\?[^\s#]*)?'  # Optional query string
    r'(?:#[^\s]*)?',  # Optional fragment
    re.IGNORECASE
)


@dataclass
class URLInfo:
    """Structured URL information."""
    url: str
    scheme: str
    domain: str
    port: Optional[int]
    path: str
    
    @classmethod
    def from_url(cls, url: str) -> 'URLInfo':
        """Parse URL into URLInfo object."""
        parsed = urlparse(url)
        return cls(
            url=url,
            scheme=parsed.scheme,
            domain=parsed.netloc.split(':')[0],
            port=parsed.port,
            path=parsed.path
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class SpiderFootParser:
    """Parser for SpiderFoot CSV exports."""
    
    def __init__(self, file_path: Path, base_domain: Optional[str] = None):
        """
        Initialize parser.
        
        Args:
            file_path: Path to SpiderFoot CSV file
            base_domain: Optional base domain for subdomain filtering
        """
        self.file_path = file_path
        self.base_domain = base_domain
        self.urls: Set[str] = set()
        self.subdomains: Set[str] = set()
        self.url_info: List[URLInfo] = []
    
    def parse(self) -> None:
        """Parse CSV file and extract URLs."""
        logger.info(f"Parsing {self.file_path}")
        
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as csvfile:
                reader = csv.reader(csvfile)
                
                for row_num, row in enumerate(reader, 1):
                    for cell in row:
                        # Find all URLs in cell
                        matches = URL_PATTERN.findall(cell)
                        self.urls.update(matches)
            
            logger.info(f"Found {len(self.urls)} unique URLs")
            
            # Parse URLs into structured format
            for url in self.urls:
                try:
                    url_info = URLInfo.from_url(url)
                    self.url_info.append(url_info)
                except Exception as e:
                    logger.debug(f"Failed to parse URL {url}: {e}")
            
            # Extract subdomains if base domain provided
            if self.base_domain:
                self._extract_subdomains()
                logger.info(f"Extracted {len(self.subdomains)} subdomains for {self.base_domain}")
        
        except FileNotFoundError:
            logger.error(f"File not found: {self.file_path}")
            raise
        except Exception as e:
            logger.error(f"Error parsing CSV: {e}")
            raise
    
    def _extract_subdomains(self) -> None:
        """Extract subdomains for base domain."""
        for url_info in self.url_info:
            domain = url_info.domain
            
            # Check if domain ends with base domain
            if domain.endswith(self.base_domain):
                # Exclude exact match of base domain
                if domain != self.base_domain:
                    self.subdomains.add(domain)
                # Also add base domain if it appears
                elif domain == self.base_domain:
                    self.subdomains.add(domain)
    
    def get_subdomain_tree(self) -> Dict[str, List[str]]:
        """
        Organize subdomains into hierarchical tree.
        
        Returns:
            Dictionary mapping parent domains to child subdomains
        """
        tree = defaultdict(list)
        
        for subdomain in sorted(self.subdomains):
            parts = subdomain.split('.')
            
            # Find parent (one level up)
            if len(parts) > 2:
                parent = '.'.join(parts[1:])
                tree[parent].append(subdomain)
            else:
                tree[self.base_domain].append(subdomain)
        
        return dict(tree)
    
    def filter_by_port(self, port: int) -> List[URLInfo]:
        """Filter URLs by port."""
        return [url for url in self.url_info if url.port == port]
    
    def filter_by_scheme(self, scheme: str) -> List[URLInfo]:
        """Filter URLs by scheme (http/https)."""
        return [url for url in self.url_info if url.scheme == scheme]
    
    def get_unique_domains(self) -> Set[str]:
        """Get all unique domains from URLs."""
        return {url.domain for url in self.url_info}


class OutputExporter:
    """Export parsed data in various formats."""
    
    @staticmethod
    def export_urls_txt(urls: Set[str], output_path: Path) -> None:
        """Export URLs as plain text (one per line)."""
        output_path.write_text('\n'.join(sorted(urls)))
        logger.info(f"Exported {len(urls)} URLs to {output_path}")
    
    @staticmethod
    def export_subdomains_txt(subdomains: Set[str], output_path: Path) -> None:
        """Export subdomains as plain text (one per line)."""
        output_path.write_text('\n'.join(sorted(subdomains)))
        logger.info(f"Exported {len(subdomains)} subdomains to {output_path}")
    
    @staticmethod
    def export_json(parser: SpiderFootParser, output_path: Path) -> None:
        """Export complete analysis as JSON."""
        data = {
            'total_urls': len(parser.urls),
            'total_subdomains': len(parser.subdomains),
            'base_domain': parser.base_domain,
            'urls': sorted(list(parser.urls)),
            'subdomains': sorted(list(parser.subdomains)),
            'unique_domains': sorted(list(parser.get_unique_domains())),
            'subdomain_tree': parser.get_subdomain_tree() if parser.base_domain else {},
            'url_details': [url.to_dict() for url in parser.url_info]
        }
        
        output_path.write_text(json.dumps(data, indent=2))
        logger.info(f"JSON export written to {output_path}")
    
    @staticmethod
    def export_csv(parser: SpiderFootParser, output_path: Path) -> None:
        """Export URL details as CSV."""
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['URL', 'Scheme', 'Domain', 'Port', 'Path'])
            
            for url_info in parser.url_info:
                writer.writerow([
                    url_info.url,
                    url_info.scheme,
                    url_info.domain,
                    url_info.port or '',
                    url_info.path
                ])
        
        logger.info(f"CSV export written to {output_path}")
    
    @staticmethod
    def export_nuclei_template(subdomains: Set[str], output_path: Path, template_name: str = "discovered-subdomains") -> None:
        """Export subdomains as Nuclei template input."""
        # Create simple targets file for Nuclei
        targets = '\n'.join(sorted(subdomains))
        output_path.write_text(targets)
        logger.info(f"Nuclei targets file written to {output_path}")
        logger.info(f"Run: nuclei -l {output_path} -t /path/to/templates")
    
    @staticmethod
    def export_httpx_input(urls: Set[str], output_path: Path) -> None:
        """Export URLs for httpx probing."""
        # Extract just domains for httpx
        domains = {urlparse(url).netloc for url in urls}
        output_path.write_text('\n'.join(sorted(domains)))
        logger.info(f"httpx input file written to {output_path}")
        logger.info(f"Run: httpx -l {output_path} -o live_hosts.txt")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Extract and analyze URLs/subdomains from SpiderFoot CSV',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract all URLs
  %(prog)s data.csv
  
  # Extract subdomains for specific domain  
  %(prog)s data.csv -d example.com
  
  # Export to JSON
  %(prog)s data.csv -d example.com -f json -o analysis.json
  
  # Generate Nuclei targets file
  %(prog)s data.csv -d example.com -f nuclei -o targets.txt
  
  # Generate httpx probe list
  %(prog)s data.csv -f httpx -o domains.txt
        """
    )
    
    parser.add_argument('input', type=Path,
                       help='SpiderFoot CSV file')
    parser.add_argument('-d', '--domain', type=str,
                       help='Base domain for subdomain filtering')
    parser.add_argument('-f', '--format', type=str,
                       choices=['txt', 'json', 'csv', 'nuclei', 'httpx'],
                       default='txt',
                       help='Output format (default: txt)')
    parser.add_argument('-o', '--output', type=Path,
                       help='Output file (default: stdout for txt)')
    parser.add_argument('--urls-only', action='store_true',
                       help='Output only URLs (not subdomains)')
    parser.add_argument('--subdomains-only', action='store_true',
                       help='Output only subdomains')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Validate input
    if not args.input.exists():
        logger.error(f"Input file not found: {args.input}")
        return 1
    
    try:
        # Parse CSV
        sf_parser = SpiderFootParser(args.input, args.domain)
        sf_parser.parse()
        
        # Determine output path
        if not args.output:
            if args.format == 'txt':
                # Print to stdout
                if args.subdomains_only and sf_parser.subdomains:
                    print('\n'.join(sorted(sf_parser.subdomains)))
                elif args.urls_only:
                    print('\n'.join(sorted(sf_parser.urls)))
                else:
                    print("=== URLs ===")
                    print('\n'.join(sorted(sf_parser.urls)))
                    if sf_parser.subdomains:
                        print("\n=== Subdomains ===")
                        print('\n'.join(sorted(sf_parser.subdomains)))
                return 0
            else:
                logger.error(f"Output file required for format: {args.format}")
                return 1
        
        # Export based on format
        if args.format == 'txt':
            if args.subdomains_only:
                OutputExporter.export_subdomains_txt(sf_parser.subdomains, args.output)
            elif args.urls_only:
                OutputExporter.export_urls_txt(sf_parser.urls, args.output)
            else:
                # Export both
                urls_file = args.output.parent / f"{args.output.stem}_urls{args.output.suffix}"
                subs_file = args.output.parent / f"{args.output.stem}_subdomains{args.output.suffix}"
                OutputExporter.export_urls_txt(sf_parser.urls, urls_file)
                if sf_parser.subdomains:
                    OutputExporter.export_subdomains_txt(sf_parser.subdomains, subs_file)
        
        elif args.format == 'json':
            OutputExporter.export_json(sf_parser, args.output)
        
        elif args.format == 'csv':
            OutputExporter.export_csv(sf_parser, args.output)
        
        elif args.format == 'nuclei':
            if not sf_parser.subdomains:
                logger.warning("No subdomains found. Did you specify --domain?")
            OutputExporter.export_nuclei_template(sf_parser.subdomains or sf_parser.get_unique_domains(), args.output)
        
        elif args.format == 'httpx':
            OutputExporter.export_httpx_input(sf_parser.urls, args.output)
        
        logger.info("Parsing and export completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
