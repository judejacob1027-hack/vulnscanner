#!/usr/bin/env python3

import subprocess
import socket
import sys
import json
import os
import re
from datetime import datetime
import xml.etree.ElementTree as ET

try:
    import requests
except ImportError:
    print("[-] requests module missing")
    print("[+] Install: sudo apt install python3-requests -y")
    sys.exit(1)


# ============================================================
#                 VULNERABILITY SCANNER
# ============================================================

VERSION = "3.0"

COMMON_PORTS = [
    21, 22, 23, 25, 53,
    80, 110, 111, 135, 139,
    143, 443, 445, 465, 587,
    993, 995, 1433, 1521,
    2049, 3306, 3389, 5432,
    5900, 6379, 8000, 8080,
    8443, 8888, 9200, 27017
]

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ============================================================
#                     HELPERS
# ============================================================

def run_command(command):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1800
        )

        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"

    except FileNotFoundError:
        return 1, "", "Nmap is not installed"

    except Exception as e:
        return 1, "", str(e)


def clean_text(value):
    if not value:
        return "-"

    return " ".join(value.split())


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


# ============================================================
#                  NMAP SCANNING
# ============================================================

def build_nmap_command(target, ports, os_detection=True):

    if ports == "ALL":
        port_args = ["-p-"]
    else:
        port_args = [
            "-p",
            ",".join(str(p) for p in ports)
        ]

    command = [
        "nmap",
        "-sV",
        "-Pn",
        "-T4",
        "--version-light"
    ] + port_args + [
        "-oX",
        "-"
    ]

    if os_detection:
        command.insert(1, "-O")

    command.append(target)

    return command


def run_nmap(target, ports):

    print("\n[+] Starting Nmap scan...")

    if ports == "ALL":
        print("[+] Full TCP port scan: 1-65535")
    else:
        print("[+] Selected TCP ports")

    print("[+] Service/version detection enabled")
    print("[+] OS detection enabled")
    print()

    command = build_nmap_command(target, ports)

    returncode, stdout, stderr = run_command(command)

    if returncode != 0:

        print("[-] Nmap scan returned an error.")

        if stderr:
            print(stderr.strip())

        print("\n[+] Retrying without OS detection...")

        command = build_nmap_command(
            target,
            ports,
            os_detection=False
        )

        returncode, stdout, stderr = run_command(command)

        if returncode != 0:
            print("[-] Nmap scan failed.")

            if stderr:
                print(stderr)

            sys.exit(1)

    return stdout


# ============================================================
#                    XML PARSER
# ============================================================

def parse_nmap_xml(xml_data):

    root = ET.fromstring(xml_data)

    result = {
        "host": {},
        "ports": [],
        "os": [],
        "scan_time": datetime.now().isoformat()
    }

    host_element = root.find("host")

    if host_element is None:
        return result

    status = host_element.find("status")

    if status is not None:
        result["host"]["state"] = status.get(
            "state",
            "-"
        )

    addresses = host_element.findall("address")

    for address in addresses:

        addr_type = address.get("addrtype")
        addr = address.get("addr")

        if addr_type == "ipv4":
            result["host"]["ipv4"] = addr

        elif addr_type == "ipv6":
            result["host"]["ipv6"] = addr

        elif addr_type == "mac":
            result["host"]["mac"] = addr

    hostname = host_element.find(
        "./hostnames/hostname"
    )

    if hostname is not None:
        result["host"]["hostname"] = hostname.get(
            "name",
            "-"
        )

    for port in host_element.findall(
        "./ports/port"
    ):

        port_number = port.get("portid")
        protocol = port.get("protocol", "tcp")

        state_element = port.find("state")

        state = "-"
        reason = "-"

        if state_element is not None:
            state = state_element.get(
                "state",
                "-"
            )

            reason = state_element.get(
                "reason",
                "-"
            )

        service_element = port.find("service")

        service = {
            "name": "-",
            "product": "-",
            "version": "-",
            "extrainfo": "-",
            "cpe": []
        }

        if service_element is not None:

            service["name"] = service_element.get(
                "name",
                "-"
            )

            service["product"] = service_element.get(
                "product",
                "-"
            )

            service["version"] = service_element.get(
                "version",
                "-"
            )

            service["extrainfo"] = service_element.get(
                "extrainfo",
                "-"
            )

            for cpe in service_element.findall("cpe"):

                if cpe.text:
                    service["cpe"].append(cpe.text)

        result["ports"].append({
            "port": int(port_number),
            "protocol": protocol,
            "state": state,
            "reason": reason,
            "service": service
        })

    osmatch_elements = host_element.findall(
        "./os/osmatch"
    )

    for osmatch in osmatch_elements:

        os_name = osmatch.get(
            "name",
            "-"
        )

        accuracy = osmatch.get(
            "accuracy",
            "-"
        )

        osclass = osmatch.find("osclass")

        family = "-"
        vendor = "-"
        generation = "-"
        ostype = "-"
        cpe = []

        if osclass is not None:

            family = osclass.get(
                "osfamily",
                "-"
            )

            vendor = osclass.get(
                "vendor",
                "-"
            )

            generation = osclass.get(
                "osgen",
                "-"
            )

            ostype = osclass.get(
                "type",
                "-"
            )

            for cpe_element in osclass.findall("cpe"):

                if cpe_element.text:
                    cpe.append(
                        cpe_element.text
                    )

        result["os"].append({
            "name": os_name,
            "accuracy": accuracy,
            "family": family,
            "vendor": vendor,
            "generation": generation,
            "type": ostype,
            "cpe": cpe
        })

    return result


# ============================================================
#                OS / DISTRIBUTION DISPLAY
# ============================================================

def print_os_detection(os_data):

    print("\n" + "=" * 70)
    print("OS DETECTION")
    print("=" * 70)

    if not os_data:

        print("OS Family      : Unknown")
        print("Distribution   : Unknown")
        print("Confidence     : Unknown")

        print(
            "\n[!] OS detection could not be determined."
        )

        return

    best = os_data[0]

    name = best.get("name", "-")
    family = best.get("family", "-")
    vendor = best.get("vendor", "-")
    generation = best.get("generation", "-")
    accuracy = best.get("accuracy", "-")

    print(f"OS Family      : {family}")
    print(f"OS Name        : {name}")
    print(f"Vendor         : {vendor}")
    print(f"Generation     : {generation}")
    print(f"Confidence     : {accuracy}%")

    distribution = "Unknown"

    combined = (
        name + " " +
        family + " " +
        vendor
    ).lower()

    distro_names = [
        "kali",
        "ubuntu",
        "debian",
        "fedora",
        "centos",
        "red hat",
        "rhel",
        "rocky",
        "almalinux",
        "arch",
        "opensuse",
        "suse",
        "amazon linux",
        "oracle linux"
    ]

    for distro in distro_names:

        if distro in combined:
            distribution = distro.title()
            break

    print(f"Distribution   : {distribution}")

    print("=" * 70)


# ============================================================
#                  SERVICE DISPLAY
# ============================================================

def print_ports(ports):

    print("\n" + "=" * 85)
    print("PORT / SERVICE DETECTION")
    print("=" * 85)

    print(
        f"{'PORT':<12}"
        f"{'STATE':<12}"
        f"{'SERVICE':<18}"
        f"{'VERSION'}"
    )

    print("-" * 85)

    for item in ports:

        if item["state"] not in (
            "open",
            "filtered"
        ):
            continue

        service = item["service"]

        version = service.get(
            "product",
            "-"
        )

        service_version = service.get(
            "version",
            ""
        )

        extra = service.get(
            "extrainfo",
            ""
        )

        if service_version:
            version += " " + service_version

        if extra:
            version += " " + extra

        print(
            f"{item['port']}/{item['protocol']:<7}"
            f"{item['state']:<12}"
            f"{service.get('name', '-'):<18}"
            f"{clean_text(version)}"
        )

    print("=" * 85)


# ============================================================
#                    CVE LOOKUP
# ============================================================

def get_search_keyword(service):

    product = service.get(
        "product",
        ""
    )

    name = service.get(
        "name",
        ""
    )

    if product and product != "-":
        return product

    if name and name != "-":
        return name

    return ""


def get_cvss(cve):

    metrics = cve.get(
        "metrics",
        {}
    )

    if "cvssMetricV40" in metrics:

        metric = metrics["cvssMetricV40"][0]

        data = metric.get(
            "cvssData",
            {}
        )

        return (
            data.get("baseScore"),
            data.get("baseSeverity")
        )

    for key in (
        "cvssMetricV31",
        "cvssMetricV30"
    ):

        if key in metrics:

            metric = metrics[key][0]

            data = metric.get(
                "cvssData",
                {}
            )

            return (
                data.get("baseScore"),
                data.get("baseSeverity")
            )

    return None, None


def get_description(cve):

    descriptions = cve.get(
        "descriptions",
        []
    )

    for description in descriptions:

        if description.get("lang") == "en":

            return clean_text(
                description.get(
                    "value",
                    ""
                )
            )

    return "-"


def search_nvd(service):

    product = service.get(
        "product",
        ""
    )

    version = service.get(
        "version",
        ""
    )

    name = service.get(
        "name",
        ""
    )

    if not product or product == "-":
        product = name

    if not product or product == "-":
        return []

    keyword = f"{product}"

    if version and version != "-":
        keyword += f" {version}"

    print(
        f"    [*] NVD lookup: {keyword}"
    )

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20
    }

    try:

        response = requests.get(
            NVD_API,
            params=params,
            timeout=20,
            headers={
                "User-Agent":
                "MyVulnerabilityScanner/3.0"
            }
        )

        if response.status_code != 200:

            print(
                f"    [-] NVD HTTP {response.status_code}"
            )

            return []

        data = response.json()

    except requests.RequestException as e:

        print(
            f"    [-] NVD request failed: {e}"
        )

        return []

    vulnerabilities = []

    for item in data.get(
        "vulnerabilities",
        []
    ):

        cve = item.get(
            "cve",
            {}
        )

        cve_id = cve.get(
            "id",
            "-"
        )

        score, severity = get_cvss(cve)

        description = get_description(cve)

        published = cve.get(
            "published",
            "-"
        )

        vulnerabilities.append({
            "cve": cve_id,
            "score": score,
            "severity": severity,
            "published": published,
            "description": description
        })

    return vulnerabilities


# ============================================================
#               AUTOMATIC VULNERABILITY SCAN
# ============================================================

def vulnerability_scan(ports):

    print("\n" + "=" * 85)
    print("AUTOMATIC VULNERABILITY CHECK")
    print("=" * 85)

    all_vulnerabilities = []

    for item in ports:

        if item["state"] != "open":
            continue

        service = item["service"]

        product = service.get(
            "product",
            "-"
        )

        version = service.get(
            "version",
            "-"
        )

        if product == "-" and version == "-":
            continue

        print(
            f"\n[+] {item['port']}/"
            f"{item['protocol']} "
            f"{product} {version}"
        )

        findings = search_nvd(
            service
        )

        seen = set()

        for finding in findings:

            if finding["cve"] in seen:
                continue

            seen.add(
                finding["cve"]
            )

            finding["port"] = item["port"]

            finding["protocol"] = item[
                "protocol"
            ]

            finding["service"] = service.get(
                "name",
                "-"
            )

            finding["product"] = product
            finding["version"] = version

            all_vulnerabilities.append(
                finding
            )

    print("\n" + "-" * 85)

    if not all_vulnerabilities:

        print(
            "[+] No CVE matches returned."
        )

    else:

        print(
            f"[!] Potential CVE findings: "
            f"{len(all_vulnerabilities)}"
        )

    print("=" * 85)

    return all_vulnerabilities


# ============================================================
#                     REPORTING
# ============================================================

def create_report_directory():

    os.makedirs(
        "reports",
        exist_ok=True
    )


def safe_filename(target):

    return re.sub(
        r"[^a-zA-Z0-9_.-]",
        "_",
        target
    )


def save_json_report(
    target,
    target_ip,
    scan_data
):

    create_report_directory()

    filename = (
        f"reports/"
        f"{safe_filename(target)}"
        f"_report.json"
    )

    report = {
        "scanner": {
            "name": "My Vulnerability Scanner",
            "version": VERSION
        },
        "target": target,
        "target_ip": target_ip,
        "scan_time": datetime.now().isoformat(),
        "results": scan_data
    }

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    return filename


def save_text_report(
    target,
    target_ip,
    scan_data
):

    create_report_directory()

    filename = (
        f"reports/"
        f"{safe_filename(target)}"
        f"_report.txt"
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "MY VULNERABILITY SCANNER\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        file.write(
            f"Target : {target}\n"
        )

        file.write(
            f"IP     : {target_ip}\n"
        )

        file.write(
            f"Time   : "
            f"{datetime.now().isoformat()}\n\n"
        )

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            "OS DETECTION\n"
        )

        file.write(
            "=" * 70 + "\n"
        )

        if scan_data["os"]:

            best = scan_data["os"][0]

            file.write(
                f"Family     : "
                f"{best.get('family', '-')}\n"
            )

            file.write(
                f"Name       : "
                f"{best.get('name', '-')}\n"
            )

            file.write(
                f"Vendor     : "
                f"{best.get('vendor', '-')}\n"
            )

            file.write(
                f"Generation : "
                f"{best.get('generation', '-')}\n"
            )

            file.write(
                f"Confidence : "
                f"{best.get('accuracy', '-')}%\n"
            )

        else:

            file.write(
                "OS detection unavailable\n"
            )

        file.write(
            "\n" +
            "=" * 70 +
            "\n"
        )

        file.write(
            "OPEN / FILTERED PORTS\n"
        )

        file.write(
            "=" * 70 + "\n"
        )

        for item in scan_data["ports"]:

            if item["state"] not in (
                "open",
                "filtered"
            ):
                continue

            service = item["service"]

            file.write(
                f"{item['port']}/"
                f"{item['protocol']} "
                f"{item['state']} "
                f"{service.get('name', '-')}"
            )

            file.write(
                f" {service.get('product', '-')}"
            )

            file.write(
                f" {service.get('version', '-')}\n"
            )

        file.write(
            "\n" +
            "=" * 70 +
            "\n"
        )

        file.write(
            "POTENTIAL VULNERABILITIES\n"
        )

        file.write(
            "=" * 70 + "\n"
        )

        vulnerabilities = scan_data[
            "vulnerabilities"
        ]

        if not vulnerabilities:

            file.write(
                "No CVE matches returned.\n"
            )

        else:

            for vuln in vulnerabilities:

                file.write(
                    f"\n{vuln['cve']}\n"
                )

                file.write(
                    f"Severity : "
                    f"{vuln.get('severity', '-')}\n"
                )

                file.write(
                    f"CVSS     : "
                    f"{vuln.get('score', '-')}\n"
                )

                file.write(
                    f"Port     : "
                    f"{vuln.get('port', '-')}\n"
                )

                file.write(
                    f"Product  : "
                    f"{vuln.get('product', '-')}\n"
                )

                file.write(
                    f"Version  : "
                    f"{vuln.get('version', '-')}\n"
                )

                file.write(
                    f"Description:\n"
                    f"{vuln.get('description', '-')}\n"
                )

        file.write(
            "\n" +
            "=" * 70 +
            "\n"
        )

        file.write(
            "IMPORTANT: CVE matches are potential findings "
            "based on detected product/version. "
            "They are not confirmation that the target is exploitable.\n"
        )

    return filename


# ============================================================
#                       MAIN
# ============================================================

def main():

    print("=" * 85)

    print(
        "             MY VULNERABILITY SCANNER v3.0"
    )

    print("=" * 85)

    target = input(
        "\nTarget IP / Hostname: "
    ).strip()

    if not target:

        print(
            "[-] Target required."
        )

        sys.exit(1)

    target_ip = resolve_target(
        target
    )

    if not target_ip:

        print(
            "[-] Could not resolve target."
        )

        sys.exit(1)

    print(
        f"\nTarget IP : {target_ip}"
    )

    print("\nScan type:")
    print("1. Common ports")
    print("2. All TCP ports")
    print("3. Custom port range")

    choice = input(
        "Select [1/2/3]: "
    ).strip()

    if choice == "1":

        ports = COMMON_PORTS

    elif choice == "2":

        ports = "ALL"

    elif choice == "3":

        try:

            start = int(
                input("Start port: ")
            )

            end = int(
                input("End port: ")
            )

            if start < 1 or end > 65535:
                raise ValueError

            if start > end:
                raise ValueError

            ports = list(
                range(
                    start,
                    end + 1
                )
            )

        except ValueError:

            print(
                "[-] Invalid port range."
            )

            sys.exit(1)

    else:

        print(
            "[-] Invalid choice."
        )

        sys.exit(1)

    if ports == "ALL":

        print(
            "\n[+] All TCP ports selected: 1-65535"
        )

    else:

        print(
            f"\n[+] Ports selected: {len(ports)}"
        )

    # --------------------------------------------------------
    # NMAP
    # --------------------------------------------------------

    xml_data = run_nmap(
        target,
        ports
    )

    # --------------------------------------------------------
    # Parse
    # --------------------------------------------------------

    try:

        results = parse_nmap_xml(
            xml_data
        )

    except ET.ParseError as e:

        print(
            f"[-] Could not parse Nmap XML: {e}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    print_ports(
        results["ports"]
    )

    print_os_detection(
        results["os"]
    )

    # --------------------------------------------------------
    # Vulnerability checking
    # --------------------------------------------------------

    vulnerabilities = vulnerability_scan(
        results["ports"]
    )

    results["vulnerabilities"] = (
        vulnerabilities
    )

    # --------------------------------------------------------
    # Reports
    # --------------------------------------------------------

    print(
        "\n[+] Generating reports..."
    )

    txt_report = save_text_report(
        target,
        target_ip,
        results
    )

    json_report = save_json_report(
        target,
        target_ip,
        results
    )

    print(
        f"[+] TXT report  : {txt_report}"
    )

    print(
        f"[+] JSON report : {json_report}"
    )

    print("\n" + "=" * 85)
    print("SCAN COMPLETED")
    print("=" * 85)


if __name__ == "__main__":
    main()
