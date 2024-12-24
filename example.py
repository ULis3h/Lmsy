# -*- coding: utf-8 -*-
from vuln_detector import VulnDetector

def main():
    # Create detector instance
    detector = VulnDetector()

    # Add a known vulnerable site example
    try:
        detector.add_vulnerable_site(
            url="https://example.com",
            vulnerability_type="XSS",
            vulnerability_details={
                "severity": "high",
                "description": "Reflected XSS in search parameter"
            }
        )
        print("Successfully added vulnerable site")
    except Exception as e:
        print("Error adding site: {}".format(e))

    # Analyze a URL
    try:
        result = detector.analyze_url("https://example.com")
        print("\nAnalysis result:")
        print(result)
    except Exception as e:
        print("Error analyzing URL: {}".format(e))

if __name__ == "__main__":
    main()
