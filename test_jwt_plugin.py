#!/usr/bin/env python3
"""
Kong JWT Claims to Headers Plugin Test Suite
"""

import requests
import jwt
import json
import time
import datetime
from typing import Dict, Any, Optional, Tuple
import argparse
import sys

class KongJWTPluginTester:
    def __init__(self, admin_url: str = "http://localhost:8001", proxy_url: str = "http://localhost:8000"):
        self.admin_url = admin_url.rstrip('/')
        self.proxy_url = proxy_url.rstrip('/')
        self.session = requests.Session()
        self.test_data = {}
        
    def log(self, message: str, level: str = "INFO"):
        """Simple logging function"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")

    def make_request(self, method: str, url: str, **kwargs) -> Tuple[bool, requests.Response]:
        """Make HTTP request with error handling"""
        try:
            response = self.session.request(method, url, **kwargs)
            return True, response
        except requests.exceptions.RequestException as e:
            self.log(f"Request failed: {e}", "ERROR")
            return False, None

    def test_kong_health(self) -> bool:
        """Test if Kong is running and accessible"""
        self.log("Testing Kong health...")
        
        success, response = self.make_request("GET", f"{self.admin_url}/status")
        if not success or response.status_code != 200:
            self.log("Kong admin API is not accessible", "ERROR")
            return False
            
        success, response = self.make_request("GET", f"{self.proxy_url}")
        if not success:
            self.log("Kong proxy is not accessible", "ERROR")
            return False
            
        self.log("✅ Kong is healthy and accessible")
        return True

    def test_plugin_available(self) -> bool:
        """Test if custom plugin is loaded"""
        self.log("Checking if jwt-claims-to-headers plugin is available...")
        
        success, response = self.make_request("GET", f"{self.admin_url}/plugins/enabled")
        if not success or response.status_code != 200:
            self.log("Failed to get enabled plugins", "ERROR")
            return False
            
        enabled_plugins = response.json().get("enabled_plugins", [])
        if "jwt-claims-to-headers" not in enabled_plugins:
            self.log("❌ jwt-claims-to-headers plugin is not enabled", "ERROR")
            self.log(f"Available plugins: {enabled_plugins}", "DEBUG")
            return False
            
        self.log("✅ jwt-claims-to-headers plugin is available")
        return True

    def cleanup_test_resources(self) -> bool:
        """Clean up any existing test resources"""
        self.log("Cleaning up existing test resources...")

        # Delete routes for test-service
        success, response = self.make_request("GET", f"{self.admin_url}/services/test-service/routes")
        if success and response.status_code == 200:
            routes = response.json().get("data", [])
            for route in routes:
                self.make_request("DELETE", f"{self.admin_url}/routes/{route['id']}")

        # Delete plugins for test-service
        success, response = self.make_request("GET", f"{self.admin_url}/services/test-service/plugins")
        if success and response.status_code == 200:
            plugins = response.json().get("data", [])
            for plugin in plugins:
                self.make_request("DELETE", f"{self.admin_url}/plugins/{plugin['id']}")

        # Delete service
        self.make_request("DELETE", f"{self.admin_url}/services/test-service")

        # Delete consumer and its JWT credentials
        success, response = self.make_request("GET", f"{self.admin_url}/consumers/testuser/jwt")
        if success and response.status_code == 200:
            jwts = response.json().get("data", [])
            for jwt_cred in jwts:
                self.make_request("DELETE", f"{self.admin_url}/consumers/testuser/jwt/{jwt_cred['id']}")
        self.make_request("DELETE", f"{self.admin_url}/consumers/testuser")

        self.log("✅ Cleanup completed")
        return True

    def setup_test_service(self) -> bool:
        """Create test service and route"""
        self.log("Setting up test service and route...")
        
        # Create service
        service_data = {
            "name": "test-service",
            "url": "http://httpbin.org/headers"
        }
        
        success, response = self.make_request("POST", f"{self.admin_url}/services/", json=service_data)
        if not success or response.status_code != 201:
            self.log(f"Failed to create service: {response.status_code} : {response.text if response else 'No response'}", "ERROR")
            return False
            
        service_info = response.json()
        self.test_data['service_id'] = service_info['id']
        self.log(f"✅ Service created with ID: {service_info['id']}")
        
        # Create route
        route_data = {
            "hosts": ["test.local"],
            "service": {"id": service_info['id']}
        }
        
        success, response = self.make_request("POST", f"{self.admin_url}/routes/", json=route_data)
        if not success or response.status_code != 201:
            self.log(f"Failed to create route: {response.text if response else 'No response'}", "ERROR")
            return False
            
        route_info = response.json()
        self.test_data['route_id'] = route_info['id']
        self.log(f"✅ Route created with ID: {route_info['id']}")
        return True

    def setup_jwt_authentication(self) -> bool:
        """Setup JWT authentication"""
        self.log("Setting up JWT authentication...")
        
        # Create consumer
        consumer_data = {"username": "testuser"}
        success, response = self.make_request("POST", f"{self.admin_url}/consumers/", json=consumer_data)
        if not success or response.status_code != 201:
            self.log(f"Failed to create consumer: {response.text if response else 'No response'}", "ERROR")
            return False
            
        consumer_info = response.json()
        self.test_data['consumer_id'] = consumer_info['id']
        self.log(f"✅ Consumer created: {consumer_info['username']}")
        
        # Create JWT credential
        jwt_data = {
            "key": "test-issuer",
            "secret": "my-secret-key-for-testing-jwt-plugin"
        }
        
        success, response = self.make_request("POST", f"{self.admin_url}/consumers/testuser/jwt", json=jwt_data)
        if not success or response.status_code != 201:
            self.log(f"Failed to create JWT credential: {response.text if response else 'No response'}", "ERROR")
            return False
            
        jwt_info = response.json()
        self.test_data['jwt_key'] = jwt_info['key']
        self.test_data['jwt_secret'] = jwt_info['secret']
        self.log(f"✅ JWT credential created for issuer: {jwt_info['key']}")
        
        # Enable JWT plugin on service
        jwt_plugin_data = {
            "name": "jwt",
            "service": {"id": self.test_data['service_id']}
        }
        
        success, response = self.make_request("POST", f"{self.admin_url}/plugins/", json=jwt_plugin_data)
        if not success or response.status_code != 201:
            self.log(f"Failed to enable JWT plugin: {response.text if response else 'No response'}", "ERROR")
            return False
            
        jwt_plugin_info = response.json()
        self.test_data['jwt_plugin_id'] = jwt_plugin_info['id']
        self.log(f"✅ JWT plugin enabled with ID: {jwt_plugin_info['id']}")
        return True

    def enable_custom_plugin(self) -> bool:
        """Enable the custom jwt-claims-to-headers plugin"""
        self.log("Enabling jwt-claims-to-headers plugin...")
        
        plugin_data = {
            "name": "jwt-claims-to-headers",
            "service": {"id": self.test_data['service_id']},
            "config": {
                "header_prefix": "X-USER-",
                "include_raw_token": True,
                "claims_to_exclude": ["iat", "exp", "nbf", "jti"]
            }
        }
        
        success, response = self.make_request("POST", f"{self.admin_url}/plugins/", json=plugin_data)
        if not success or response.status_code != 201:
            self.log(f"Failed to enable custom plugin: {response.text if response else 'No response'}", "ERROR")
            return False
            
        plugin_info = response.json()
        self.test_data['custom_plugin_id'] = plugin_info['id']
        self.log(f"✅ Custom plugin enabled with ID: {plugin_info['id']}")
        self.log(f"Configuration: {plugin_info['config']}")
        return True

    def generate_jwt_token(self, custom_claims: Optional[Dict[str, Any]] = None) -> str:
        """Generate a JWT token for testing"""
        default_payload = {
            "iss": self.test_data['jwt_key'],
            "sub": "test-user-123",
            "name": "John Doe",
            "email": "john.doe@example.com",
            "role": "admin",
            "department": "engineering",
            "permissions": ["read", "write", "delete"],
            "metadata": {
                "region": "us-east-1",
                "environment": "test"
            },
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        
        if custom_claims:
            default_payload.update(custom_claims)
            
        token = jwt.encode(default_payload, self.test_data['jwt_secret'], algorithm="HS256")
        self.log(f"✅ Generated JWT token with claims: {list(default_payload.keys())}")
        return token

    def test_without_jwt(self) -> bool:
        """Test request without JWT token (should fail)"""
        self.log("Testing request without JWT token...")
        
        headers = {"Host": "test.local"}
        success, response = self.make_request("GET", self.proxy_url, headers=headers)
        
        if not success:
            self.log("❌ Request failed completely", "ERROR")
            return False
            
        if response.status_code == 401:
            self.log("✅ Request correctly rejected (401) without JWT token")
            return True
        else:
            self.log(f"❌ Expected 401, got {response.status_code}", "ERROR")
            return False

    def test_with_invalid_jwt(self) -> bool:
        """Test request with invalid JWT token"""
        self.log("Testing request with invalid JWT token...")
        
        headers = {
            "Host": "test.local",
            "Authorization": "Bearer invalid.jwt.token"
        }
        
        success, response = self.make_request("GET", self.proxy_url, headers=headers)
        
        if not success:
            self.log("❌ Request failed completely", "ERROR")
            return False
            
        if response.status_code == 401:
            self.log("✅ Request correctly rejected (401) with invalid JWT token")
            return True
        else:
            self.log(f"❌ Expected 401, got {response.status_code}", "ERROR")
            return False

    def test_with_valid_jwt(self) -> bool:
        """Test request with valid JWT token and verify headers"""
        self.log("Testing request with valid JWT token...")
        
        token = self.generate_jwt_token()
        headers = {
            "Host": "test.local",
            "Authorization": f"Bearer {token}"
        }
        
        success, response = self.make_request("GET", self.proxy_url, headers=headers)
        
        if not success:
            self.log("❌ Request failed completely", "ERROR")
            return False
            
        if response.status_code != 200:
            self.log(f"❌ Expected 200, got {response.status_code}: {response.text}", "ERROR")
            return False
            
        try:
            response_data = response.json()
            received_headers = response_data.get('headers', {})
        except json.JSONDecodeError:
            self.log(f"❌ Invalid JSON response: {response.text}", "ERROR")
            return False
            
        # Check for expected headers
        expected_headers = [
            "X-User-Sub",
            "X-User-Name", 
            "X-User-Email",
            "X-User-Role",
            "X-User-Department",
            "X-User-Raw-Token"
        ]
        
        missing_headers = []
        found_headers = []
        
        for expected_header in expected_headers:
            if expected_header in received_headers:
                found_headers.append(f"{expected_header}: {received_headers[expected_header]}")
            else:
                missing_headers.append(expected_header)
                
        if missing_headers:
            self.log(f"❌ Missing expected headers: {missing_headers}", "ERROR")
            self.log(f"Available headers: {list(received_headers.keys())}", "DEBUG")
            return False
            
        self.log("✅ All expected headers found:")
        for header in found_headers:
            self.log(f"  {header}")
            
        # Verify excluded claims are not present
        excluded_claims = ["X-User-Iat", "X-User-Exp", "X-User-Nbf", "X-User-Jti"]
        found_excluded = [claim for claim in excluded_claims if claim in received_headers]
        
        if found_excluded:
            self.log(f"❌ Found excluded claims in headers: {found_excluded}", "ERROR")
            return False
            
        self.log("✅ Excluded claims correctly filtered out")
        return True

    def test_complex_claims(self) -> bool:
        """Test with complex claims including arrays and objects"""
        self.log("Testing with complex claims (arrays and objects)...")
        
        complex_claims = {
            "permissions": ["read", "write", "admin"],
            "metadata": {
                "region": "us-west-2",
                "tier": "premium",
                "features": ["feature1", "feature2"]
            },
            "groups": ["admin", "users", "developers"]
        }
        
        token = self.generate_jwt_token(complex_claims)
        headers = {
            "Host": "test.local",
            "Authorization": f"Bearer {token}"
        }
        
        success, response = self.make_request("GET", self.proxy_url, headers=headers)
        
        if not success or response.status_code != 200:
            self.log(f"❌ Request failed: {response.status_code if response else 'No response'}", "ERROR")
            return False
            
        try:
            response_data = response.json()
            received_headers = response_data.get('headers', {})
        except json.JSONDecodeError:
            self.log(f"❌ Invalid JSON response: {response.text}", "ERROR")
            return False
            
        # Check complex claims are properly JSON encoded
        complex_header_checks = [
            ("X-User-Permissions", "permissions"),
            ("X-User-Metadata", "metadata"),
            ("X-User-Groups", "groups")
        ]
        
        for header_name, claim_name in complex_header_checks:
            if header_name not in received_headers:
                self.log(f"❌ Missing complex claim header: {header_name}", "ERROR")
                return False
                
            try:
                parsed_value = json.loads(received_headers[header_name])
                self.log(f"✅ {header_name}: {received_headers[header_name]}")
            except json.JSONDecodeError:
                self.log(f"❌ Complex claim {header_name} is not valid JSON: {received_headers[header_name]}", "ERROR")
                return False
                
        return True

    def run_all_tests(self) -> bool:
        """Run all tests in sequence"""
        self.log("=" * 60)
        self.log("STARTING KONG JWT CLAIMS TO HEADERS PLUGIN TESTS")
        self.log("=" * 60)
        
        tests = [
            ("Kong Health Check", self.test_kong_health),
            ("Plugin Availability", self.test_plugin_available), 
            ("Cleanup Resources", self.cleanup_test_resources),
            ("Setup Test Service", self.setup_test_service),
            ("Setup JWT Authentication", self.setup_jwt_authentication),
            ("Enable Custom Plugin", self.enable_custom_plugin),
            ("Test Without JWT", self.test_without_jwt),
            ("Test Invalid JWT", self.test_with_invalid_jwt),
            ("Test Valid JWT", self.test_with_valid_jwt),
            ("Test Complex Claims", self.test_complex_claims)
        ]
        
        results = []
        for test_name, test_func in tests:
            self.log(f"\n--- Running: {test_name} ---")
            try:
                result = test_func()
                results.append((test_name, result))
                if not result:
                    self.log(f"❌ {test_name} FAILED", "ERROR")
                    break
            except Exception as e:
                self.log(f"❌ {test_name} FAILED with exception: {e}", "ERROR")
                results.append((test_name, False))
                break
                
        # Print summary
        self.log("\n" + "=" * 60)
        self.log("TEST RESULTS SUMMARY")
        self.log("=" * 60)
        
        passed = 0
        for test_name, result in results:
            status = "✅ PASS" if result else "❌ FAIL"
            self.log(f"{status}: {test_name}")
            if result:
                passed += 1
                
        self.log(f"\nTotal: {len(results)} tests, {passed} passed, {len(results) - passed} failed")
        
        return all(result for _, result in results)

def main():
    parser = argparse.ArgumentParser(description="Kong JWT Claims to Headers Plugin Tester")
    parser.add_argument("--admin-url", default="http://localhost:8001", help="Kong Admin API URL")
    parser.add_argument("--proxy-url", default="http://localhost:8000", help="Kong Proxy URL")
    parser.add_argument("--test", choices=[
        "health", "plugin", "cleanup", "setup-service", "setup-jwt", 
        "enable-plugin", "no-jwt", "invalid-jwt", "valid-jwt", "complex", "all"
    ], default="all", help="Specific test to run")
    
    args = parser.parse_args()
    
    tester = KongJWTPluginTester(args.admin_url, args.proxy_url)
    
    # Map test names to functions
    test_map = {
        "health": tester.test_kong_health,
        "plugin": tester.test_plugin_available,
        "cleanup": tester.cleanup_test_resources,
        "setup-service": tester.setup_test_service,
        "setup-jwt": tester.setup_jwt_authentication,
        "enable-plugin": tester.enable_custom_plugin,
        "no-jwt": tester.test_without_jwt,
        "invalid-jwt": tester.test_with_invalid_jwt,
        "valid-jwt": tester.test_with_valid_jwt,
        "complex": tester.test_complex_claims,
        "all": tester.run_all_tests
    }
    
    if args.test in test_map:
        success = test_map[args.test]()
        sys.exit(0 if success else 1)
    else:
        print(f"Unknown test: {args.test}")
        sys.exit(1)

if __name__ == "__main__":
    main()