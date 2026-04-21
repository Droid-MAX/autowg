#!/usr/bin/env python
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


def find_openssl():
    try:
        subprocess.run(["openssl", "version"], capture_output=True, check=True)
        return "openssl"
    except (subprocess.SubprocessError, FileNotFoundError):
        print("OpenSSL not found in PATH. Please install OpenSSL or add it to PATH.", file=sys.stderr)
        return None


def run_cmd(cmd, description=None):
    if description:
        print(f"  {description}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"  ERROR: Command failed: {' '.join(cmd)}", file=sys.stderr)
        raise


def create_ca(ca_cert, ca_key, validity_days):
    openssl = find_openssl()
    if not openssl:
        return False

    print("Creating root CA certificate...")
    try:
        run_cmd([openssl, "genrsa", "-out", ca_key, "2048"], "Generating CA private key")

        ca_config = Path("ca-ext.cnf")
        config_content = """[req]
distinguished_name = req_distinguished_name
prompt = no
x509_extensions = v3_ca

[req_distinguished_name]
CN = AutoWG-Root-CA

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
"""
        ca_config.write_text(config_content, encoding="ascii")

        run_cmd([
            openssl, "req", "-x509", "-new", "-nodes",
            "-key", ca_key, "-sha256", "-days", str(validity_days),
            "-out", ca_cert, "-config", str(ca_config)
        ], "Generating self-signed CA certificate")

        ca_config.unlink(missing_ok=True)

        print("\nRoot CA certificate created successfully:")
        print(f"  CA Certificate: {ca_cert}")
        print(f"  CA Private Key: {ca_key}")
        print(f"  Validity: {validity_days} days")
        return True
    except subprocess.CalledProcessError:
        print("Failed to create root CA", file=sys.stderr)
        return False


def create_server_cert(server_name, dns_names, ip_addresses, ca_cert, ca_key, output_dir, validity_days):
    openssl = find_openssl()
    if not openssl:
        return False

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    server_key = output_path / "server-key.pem"
    server_csr = output_path / "server.csr"
    server_cert = output_path / "server-cert.pem"
    ext_config = output_path / "server-ext.cnf"

    print(f"Creating server certificate with SAN for: {server_name}")

    try:
        run_cmd([openssl, "genrsa", "-out", str(server_key), "2048"], "Generating server private key")
        if not server_key.exists():
            print("  ERROR: Failed to create server private key", file=sys.stderr)
            return False

        dns_list = [d.strip() for d in dns_names.split(',') if d.strip()]
        ip_list = [ip.strip() for ip in ip_addresses.split(',') if ip.strip()]

        if server_name not in dns_list:
            dns_list.insert(0, server_name)

        config_lines = [
            "[req]",
            "distinguished_name = req_distinguished_name",
            "req_extensions = v3_req",
            "prompt = no",
            "",
            "[req_distinguished_name]",
            f"CN = {server_name}",
            "",
            "[v3_req]",
            "keyUsage = digitalSignature, keyEncipherment",
            "extendedKeyUsage = serverAuth",
            "subjectAltName = @alt_names",
            "",
            "[alt_names]",
        ]
        idx = 1
        for dns in dns_list:
            config_lines.append(f"DNS.{idx} = {dns}")
            idx += 1
        ip_idx = 1
        for ip in ip_list:
            config_lines.append(f"IP.{ip_idx} = {ip}")
            ip_idx += 1

        ext_config.write_text("\n".join(config_lines), encoding="ascii")
        print(f"  Extension config file created: {ext_config}")

        run_cmd([openssl, "req", "-new", "-key", str(server_key), "-out", str(server_csr), "-config", str(ext_config)],
                "Generating CSR")
        if not server_csr.exists():
            print("  ERROR: Failed to create CSR", file=sys.stderr)
            return False

        run_cmd([
            openssl, "x509", "-req", "-in", str(server_csr),
            "-days", str(validity_days), "-CA", ca_cert, "-CAkey", ca_key,
            "-CAcreateserial", "-out", str(server_cert),
            "-extfile", str(ext_config), "-extensions", "v3_req"
        ], "Signing certificate")
        if not server_cert.exists():
            print("  ERROR: Failed to create server certificate", file=sys.stderr)
            return False

        server_csr.unlink(missing_ok=True)
        ext_config.unlink(missing_ok=True)

        print("\nServer certificate created successfully:")
        print(f"  Private key: {server_key}")
        print(f"  Certificate: {server_cert}")
        print(f"  Validity: {validity_days} days")
        return True

    except subprocess.CalledProcessError as e:
        print(f"Failed to create server certificate: {e}", file=sys.stderr)
        return False


def create_directbcd_cert(client_id, ca_cert, ca_key, output_dir, validity_days):
    if not 1 <= client_id <= 9999:
        print("Client ID must be between 1 and 9999 for direct-bcd mode", file=sys.stderr)
        return False

    openssl = find_openssl()
    if not openssl:
        return False

    client_key = Path(output_dir) / f"client-{client_id}.key"
    client_csr = Path(output_dir) / f"client-{client_id}.csr"
    client_cert = Path(output_dir) / f"client-{client_id}.crt"

    print(f"Creating direct-bcd client certificate for ID: {client_id}")

    try:
        run_cmd([
            openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(client_key), "-out", str(client_csr),
            "-subj", f"/CN={client_id}"
        ])

        run_cmd([
            openssl, "x509", "-req", "-in", str(client_csr),
            "-days", str(validity_days), "-CA", ca_cert, "-CAkey", ca_key,
            "-CAcreateserial", "-out", str(client_cert)
        ])

        client_csr.unlink(missing_ok=True)

        print("\nCertificate created successfully:")
        print(f"  Private key: {client_key}")
        print(f"  Certificate: {client_cert}")
        return True

    except subprocess.CalledProcessError as e:
        print(f"Failed to create certificate: {e}", file=sys.stderr)
        return False


def create_metans_cert(client_name, ca_cert, ca_key, output_dir, validity_days):
    if not client_name or client_name.strip() == "":
        print("Client name is required for metans mode", file=sys.stderr)
        return False

    openssl = find_openssl()
    if not openssl:
        return False

    safe_name = re.sub(r"[^a-zA-Z0-9-]", "-", client_name)
    client_key = Path(output_dir) / f"client-{safe_name}.key"
    client_csr = Path(output_dir) / f"client-{safe_name}.csr"
    client_cert = Path(output_dir) / f"client-{safe_name}.crt"

    print(f"Creating metans client certificate for name: {client_name}")

    try:
        run_cmd([
            openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(client_key), "-out", str(client_csr),
            "-subj", f"/CN={client_name}"
        ])

        run_cmd([
            openssl, "x509", "-req", "-in", str(client_csr),
            "-days", str(validity_days), "-CA", ca_cert, "-CAkey", ca_key,
            "-CAcreateserial", "-out", str(client_cert)
        ])

        client_csr.unlink(missing_ok=True)

        print("\nCertificate created successfully:")
        print(f"  Private key: {client_key}")
        print(f"  Certificate: {client_cert}")
        print(f"  CN: {client_name}")
        return True

    except subprocess.CalledProcessError as e:
        print(f"Failed to create certificate: {e}", file=sys.stderr)
        return False


def list_certificates(output_dir):
    print("=== Client Certificates ===")

    cert_files = list(Path(output_dir).glob("client-*.crt"))
    if not cert_files:
        print(f"No client certificates found in {output_dir}")
        return

    openssl = find_openssl()
    for cert in cert_files:
        print(f"\nCertificate: {cert.name}")
        if openssl:
            try:
                result = subprocess.run(
                    [openssl, "x509", "-in", str(cert), "-noout", "-subject", "-dates"],
                    capture_output=True, text=True, check=True
                )
                print(f"  {result.stdout.strip()}")
            except subprocess.CalledProcessError:
                print("  Unable to read certificate details")


def check_certificate(client_name, client_id, output_dir):
    openssl = find_openssl()
    if not openssl:
        return

    has_name = bool(client_name and client_name.strip())
    has_id = client_id is not None and 1 <= client_id <= 9999

    if has_name and has_id:
        print("Error: Cannot use both --client-name and --client-id simultaneously", file=sys.stderr)
        return
    if not has_name and not has_id:
        print("Error: Client ID (1-9999) or Client name is required to check certificate", file=sys.stderr)
        return

    if has_id:
        cert_path = Path(output_dir) / f"client-{client_id}.crt"
    else:
        safe_name = re.sub(r"[^a-zA-Z0-9-]", "-", client_name)
        cert_path = Path(output_dir) / f"client-{safe_name}.crt"

    if cert_path.exists():
        print(f"Certificate found: {cert_path}")
        try:
            result = subprocess.run(
                [openssl, "x509", "-in", str(cert_path), "-noout", "-subject", "-dates", "-serial"],
                capture_output=True, text=True, check=True
            )
            print("Certificate details:")
            for line in result.stdout.strip().splitlines():
                print(f"  {line}")

            enddate = subprocess.run(
                [openssl, "x509", "-in", str(cert_path), "-noout", "-enddate"],
                capture_output=True, text=True, check=True
            )
            print(f"  {enddate.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to read certificate details: {e}", file=sys.stderr)
    else:
        print(f"Certificate not found: {cert_path}")


def deploy_certificate(client_name, client_id, output_dir):
    has_name = bool(client_name and client_name.strip())
    has_id = client_id is not None and 1 <= client_id <= 9999

    if has_name and has_id:
        print("Error: Cannot use both --client-name and --client-id simultaneously", file=sys.stderr)
        return
    if not has_name and not has_id:
        print("Error: Client ID (1-9999) or Client name is required to deploy certificate", file=sys.stderr)
        return

    if has_id:
        safe_name = str(client_id)
    else:
        safe_name = re.sub(r"[^a-zA-Z0-9-]", "-", client_name)

    cert_path = Path(output_dir) / f"client-{safe_name}.crt"
    key_path = Path(output_dir) / f"client-{safe_name}.key"
    ca_cert_path = Path(output_dir) / "ca-cert.pem"

    if not cert_path.exists():
        print(f"Certificate not found: {cert_path}", file=sys.stderr)
        return
    if not key_path.exists():
        print(f"Private key not found: {key_path}", file=sys.stderr)
        return

    deploy_dir = Path(output_dir) / "deploy" / safe_name
    deploy_dir.mkdir(parents=True, exist_ok=True)

    try:
        shutil.copy2(cert_path, deploy_dir)
        shutil.copy2(key_path, deploy_dir)
        if ca_cert_path.exists():
            shutil.copy2(ca_cert_path, deploy_dir)

        print(f"Certificate deployed successfully to: {deploy_dir}")
        print("Files deployed:")
        print(f"  - client-{safe_name}.crt")
        print(f"  - client-{safe_name}.key")
        if (deploy_dir / "ca-cert.pem").exists():
            print("  - ca-cert.pem")
    except Exception as e:
        print(f"Failed to deploy certificate: {e}", file=sys.stderr)


def revoke_certificate(client_name, client_id, ca_cert, ca_key, output_dir):
    openssl = find_openssl()
    if not openssl:
        return

    has_name = bool(client_name and client_name.strip())
    has_id = client_id is not None and 1 <= client_id <= 9999

    if has_name and has_id:
        print("Error: Cannot use both --client-name and --client-id simultaneously", file=sys.stderr)
        return
    if not has_name and not has_id:
        print("Error: Client ID (1-9999) or Client name is required to revoke certificate", file=sys.stderr)
        return

    if has_id:
        safe_name = str(client_id)
    else:
        safe_name = re.sub(r"[^a-zA-Z0-9-]", "-", client_name)

    cert_path = Path(output_dir) / f"client-{safe_name}.crt"

    if not cert_path.exists():
        print(f"Certificate not found: {cert_path}", file=sys.stderr)
        return

    print(f"Revoking certificate: {cert_path}")
    print("WARNING: This will add the certificate to the CRL.")
    print("Note: You need to configure Caddy to check the CRL for revocation.")

    try:
        cert_path.unlink()
        (Path(output_dir) / f"client-{safe_name}.key").unlink(missing_ok=True)
        (Path(output_dir) / f"client-{safe_name}.srl").unlink(missing_ok=True)
        print("Certificate revoked successfully")
    except Exception as e:
        print(f"Failed to revoke certificate: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="AutoWG Certificate Manager\n\n"
                    "Available actions:\n"
                    "  create-ca       - Create root CA certificate\n"
                    "  create-server   - Create server certificate with SAN\n"
                    "  create          - Create client certificate\n"
                    "  list            - List existing client certificates\n"
                    "  check           - Check certificate validity\n"
                    "  deploy          - Deploy certificate to client\n"
                    "  revoke          - Revoke client certificate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("action", nargs="?", default=None,
                        choices=["create-ca", "create-server", "create",
                                 "list", "check", "deploy", "revoke"],
                        help="Action to perform")
    parser.add_argument("--mode", choices=["direct-bcd", "metans"], default="direct-bcd",
                        help="Certificate mode (default: direct-bcd)")
    parser.add_argument("--client-id", type=int, default=0,
                        help="Client ID for direct-bcd mode (1-9999)")
    parser.add_argument("--client-name", default="",
                        help="Client name for metans mode (e.g., smart-toilet-5678)")
    parser.add_argument("--ca-cert", default="./ca-cert.pem",
                        help="CA certificate path (default: ./ca-cert.pem)")
    parser.add_argument("--ca-key", default="./ca-key.pem",
                        help="CA private key path (default: ./ca-key.pem)")
    parser.add_argument("--output-dir", default=".",
                        help="Output directory (default: .)")
    parser.add_argument("--validity-days", type=int, default=365,
                        help="Certificate validity in days (default: 365)")
    parser.add_argument("--server-name", default="localhost",
                        help="Server name for server certificate (default: localhost)")
    parser.add_argument("--dns-names", default="localhost",
                        help="DNS names for server SAN (comma-separated)")
    parser.add_argument("--ip-addresses", default="127.0.0.1",
                        help="IP addresses for server SAN (comma-separated)")

    args = parser.parse_args()

    if args.action is None:
        parser.print_help()
        return

    if args.action == "create-ca":
        create_ca(args.ca_cert, args.ca_key, args.validity_days * 10)

    elif args.action == "create-server":
        create_server_cert(
            args.server_name, args.dns_names, args.ip_addresses,
            args.ca_cert, args.ca_key, args.output_dir, args.validity_days
        )

    elif args.action == "create":
        if args.mode == "direct-bcd":
            if args.client_name:
                print("Error: --client-name cannot be used with direct-bcd mode, use --client-id instead", file=sys.stderr)
                return
            if not 1 <= args.client_id <= 9999:
                print("Error: --client-id is required and must be between 1 and 9999 for direct-bcd mode", file=sys.stderr)
                return
            create_directbcd_cert(
                args.client_id, args.ca_cert, args.ca_key,
                args.output_dir, args.validity_days
            )
        elif args.mode == "metans":
            if args.client_id != 0:
                print("Error: --client-id cannot be used with metans mode, use --client-name instead", file=sys.stderr)
                return
            if not args.client_name:
                print("Error: --client-name is required for metans mode", file=sys.stderr)
                return
            create_metans_cert(
                args.client_name, args.ca_cert, args.ca_key,
                args.output_dir, args.validity_days
            )
        else:
            print(f"Unknown mode: {args.mode}", file=sys.stderr)
            print("Supported modes: direct-bcd, metans", file=sys.stderr)

    elif args.action == "list":
        list_certificates(args.output_dir)

    elif args.action == "check":
        check_certificate(args.client_name, args.client_id, args.output_dir)

    elif args.action == "deploy":
        deploy_certificate(args.client_name, args.client_id, args.output_dir)

    elif args.action == "revoke":
        revoke_certificate(
            args.client_name, args.client_id,
            args.ca_cert, args.ca_key, args.output_dir
        )


if __name__ == "__main__":
    main()