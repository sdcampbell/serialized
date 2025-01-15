import base64
import re
import sys
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote

@dataclass
class SerializationPattern:
    name: str
    pattern: str
    description: str

@dataclass
class SerializationFinding:
    pattern_name: str
    pattern_description: str
    location: str
    field_name: str
    raw_value: str
    decoded_value: Optional[str]
    is_base64: bool
    version: Optional[str] = None

@dataclass
class HTTPRequest:
    method: str
    path: str
    headers: Dict[str, str]
    body: str

class SerializationDetector:
    def __init__(self):
        self.pickle_patterns = {
            "Protocol 0 (ASCII)": (
                r'^(I\d+\n|'           # Integer
                r'F\d+\.\d*\n|'        # Float
                r'S\'.*\'\n|'          # String
                r'V[^(){\[\]}\n]+\n|'  # Unicode String
                r'N\n|'                # None
                r'T\n|'                # True
                r'F\n|'                # False
                r'\(.*[\n\.]|'         # Tuple
                r'\[.*[\n\.]|'         # List
                r'\{.*[\n\.])'         # Dict
            ),
            "Protocol 1": r'^\((K[^KV].*q\d+h|I\d+\n)',  # More specific Protocol 1 pattern
            "Protocol 2": r'^\x80\x02',
            "Protocol 3": r'^\x80\x03',
            "Protocol 4": r'^\x80\x04|^gAS[A-Za-z0-9+/=]',  # Pattern for raw and base64 Protocol 4
            "Protocol 5": r'^\x80\x05|^(gAUV|gAWV)'
        }
        
        self.patterns = [
            # PHP pattern first to take precedence
            SerializationPattern(
                "PHP Serialization",
                r'^[OoCda]:\d+:|^array:\d+:|^string:\d+:|^i:\d+;|^b:[01];|^N;',
                "PHP serialized data using serialize()"
            ),
            SerializationPattern(
                "Java Serialization",
                r'^\xac\xed\x00\x05|rO0|^H\xf3\xb2\x8d',
                "Java serialized object data"
            ),
            SerializationPattern(
                ".NET Binary",
                r'^\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01|AAEAAAD/////|BAEAAAD/////',
                ".NET Binary Formatter serialization"
            ),
            SerializationPattern(
                "Ruby Marshal",
                r'\x04\x08[iIu:]|\x04\x08[\x22\x23]|^---\s*\n',
                "Ruby Marshal serialized data"
            ),
            SerializationPattern(
                "JSON Web Token",
                r'^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$',
                "JWT token structure"
            ),
            SerializationPattern(
                "MessagePack",
                r'^\x94|\x95|\x96|\x97|\x99|\x9a|\x9b|\x9c|\x9d|\x9e|\x9f',
                "MessagePack serialized data"
            ),
            SerializationPattern(
                "Protocol Buffers",
                r'\x0a[\x00-\xff]{2}|^\n[\x00-\xff]{2}',
                "Protobuf serialized data"
            )
        ]

    def try_base64_decode(self, data: str) -> Optional[bytes]:
        """Try to decode base64 data, with URL decoding first."""
        try:
            # First try URL decoding
            url_decoded = unquote(data)
            try:
                return base64.b64decode(url_decoded)
            except:
                try:
                    return base64.urlsafe_b64decode(url_decoded)
                except:
                    pass
            
            # If URL decoded base64 fails, try raw base64
            try:
                return base64.b64decode(data)
            except:
                return base64.urlsafe_b64decode(data)
        except:
            return None

    def check_pickle_version(self, data: str) -> Optional[str]:
        """Check which Python Pickle version the data matches."""
        for version, pattern in self.pickle_patterns.items():
            if re.search(pattern, data, re.MULTILINE):
                return version
        return None

    def check_data(self, data: str, location: str, field_name: str) -> List[SerializationFinding]:
        findings = []
        raw_findings = []
        
        # Check PHP pattern first
        php_pattern = self.patterns[0]  # PHP pattern is now first in the list
        if re.search(php_pattern.pattern, data, re.MULTILINE):
            raw_findings.append(SerializationFinding(
                pattern_name=php_pattern.name,
                pattern_description=php_pattern.description,
                location=location,
                field_name=field_name,
                raw_value=data,
                decoded_value=None,
                is_base64=False,
                version=None
            ))
        
        # Then check pickle patterns
        pickle_version = self.check_pickle_version(data)
        if pickle_version:
            raw_findings.append(SerializationFinding(
                pattern_name="Python Pickle",
                pattern_description=f"Python Pickle serialization ({pickle_version})",
                location=location,
                field_name=field_name,
                raw_value=data,
                decoded_value=None,
                is_base64=False,
                version=pickle_version
            ))

        # Check other patterns
        for pattern in self.patterns[1:]:  # Skip PHP pattern since we already checked it
            if re.search(pattern.pattern, data, re.MULTILINE):
                raw_findings.append(SerializationFinding(
                    pattern_name=pattern.name,
                    pattern_description=pattern.description,
                    location=location,
                    field_name=field_name,
                    raw_value=data,
                    decoded_value=None,
                    is_base64=False,
                    version=None
                ))

        # Check base64 encoded data
        decoded = self.try_base64_decode(data)
        if decoded:
            try:
                decoded_str = decoded.decode('utf-8', errors='ignore')
                # For each raw finding, check if it's actually base64 encoded
                if raw_findings:
                    # If we found patterns in raw data, let's check if they're actually base64 encoded
                    for finding in raw_findings:
                        if finding.pattern_name == "Python Pickle":
                            # For Python Pickle, we don't need to recheck the pattern since we know
                            # this is base64 encoded data. Just add the decoded value.
                            finding.decoded_value = decoded_str
                            finding.is_base64 = True
                            findings.append(finding)
                            return findings
                        elif finding.pattern_name == "PHP Serialization":
                            if re.search(php_pattern.pattern, decoded_str, re.MULTILINE):
                                finding.decoded_value = decoded_str
                                finding.is_base64 = True
                                findings.append(finding)
                                return findings
                
                # If no raw findings or they didn't match decoded data, check decoded data for new patterns
                pickle_version = self.check_pickle_version(decoded_str)
                if pickle_version:
                    findings.append(SerializationFinding(
                        pattern_name="Python Pickle",
                        pattern_description=f"Python Pickle serialization ({pickle_version})",
                        location=location,
                        field_name=field_name,
                        raw_value=data,
                        decoded_value=decoded_str,
                        is_base64=True,
                        version=pickle_version
                    ))
                    return findings

                # Check PHP pattern in decoded data
                if re.search(php_pattern.pattern, decoded_str, re.MULTILINE):
                    findings.append(SerializationFinding(
                        pattern_name=php_pattern.name,
                        pattern_description=php_pattern.description,
                        location=location,
                        field_name=field_name,
                        raw_value=data,
                        decoded_value=decoded_str,
                        is_base64=True,
                        version=None
                    ))
                    return findings

                # Check other patterns for decoded data
                for pattern in self.patterns[1:]:
                    if re.search(pattern.pattern, decoded_str, re.MULTILINE):
                        findings.append(SerializationFinding(
                            pattern_name=pattern.name,
                            pattern_description=pattern.description,
                            location=location,
                            field_name=field_name,
                            raw_value=data,
                            decoded_value=decoded_str,
                            is_base64=True,
                            version=None
                        ))
            except:
                pass
        
        # If we found any raw patterns but they weren't base64, include them
        if not findings and raw_findings:
            findings.extend(raw_findings)
        
        return findings

    def parse_raw_http(self, raw_request: str) -> HTTPRequest:
        lines = raw_request.splitlines()
        if not lines:
            raise ValueError("Empty request")

        # Parse request line
        method, path, _ = lines[0].split(' ')
        
        # Parse headers
        headers = {}
        current_line = 1
        while current_line < len(lines) and lines[current_line].strip():
            key, value = lines[current_line].split(':', 1)
            headers[key.strip()] = value.strip()
            current_line += 1
        
        # Store content-type for later use
        self.content_type = headers.get('Content-Type', '')
        
        # Get body
        body = '\n'.join(lines[current_line+1:])
        
        return HTTPRequest(method, path, headers, body)

    def analyze_request(self, raw_request: str) -> List[SerializationFinding]:
        findings = []
        request = self.parse_raw_http(raw_request)
        
        # Check headers
        for header, value in request.headers.items():
            header_findings = self.check_data(value, "Header", header)
            findings.extend(header_findings)
        
        # Check URL parameters
        if '?' in request.path:
            path, params = request.path.split('?', 1)
            params_dict = parse_qs(params)
            for param, values in params_dict.items():
                for value in values:
                    param_findings = self.check_data(value, "URL Parameter", param)
                    findings.extend(param_findings)
        
        # Check body
        if request.body:
            # For form data, parse parameters
            if "application/x-www-form-urlencoded" in self.content_type.lower():
                params = parse_qs(request.body)
                for param, values in params.items():
                    for value in values:
                        param_findings = self.check_data(value, "Form Parameter", param)
                        findings.extend(param_findings)
            else:
                body_findings = self.check_data(request.body, "Request Body", "body")
                findings.extend(body_findings)

        # Split cookie header into individual cookies
        if "Cookie" in request.headers:
            cookies = request.headers["Cookie"].split('; ')
            for cookie in cookies:
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    cookie_findings = self.check_data(value, "Cookie", name)
                    findings.extend(cookie_findings)
        
        return findings

def main():
    # Read raw request from stdin
    raw_request = sys.stdin.read()
    
    try:
        detector = SerializationDetector()
        findings = detector.analyze_request(raw_request)
        
        if findings:
            print("Serialized data detected:")
            for finding in findings:
                print(f"\n[+] {finding.pattern_name} detected")
                if finding.version:
                    print(f"    Version: {finding.version}")
                print(f"    Location: {finding.location} '{finding.field_name}'")
                print(f"    Description: {finding.pattern_description}")
                print(f"    Original value: {finding.raw_value}")
                if finding.is_base64:
                    print("    Encoding: Base64")
                    if finding.decoded_value:
                        # Replace non-ASCII characters with periods
                        readable_value = ''.join('.' if not (32 <= ord(c) <= 126) else c 
                                               for c in finding.decoded_value)
                        print(f"    Decoded value: {readable_value}")
        else:
            print("No serialized data patterns detected.")
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
