import socket
import threading
import xml.etree.ElementTree as ET
import time
import json

DEFAULT_PORT = 5555
CONTACTS_FILE = "contacts.json"
MY_IP_ADDRESS = ""

contacts = {}

def load_contacts():
    global contacts
    try:
        with open(CONTACTS_FILE, 'r') as f:
            contacts = json.load(f)
        print(f"Contacts loaded from {CONTACTS_FILE}")
    except FileNotFoundError:
        print(f"Contacts file ({CONTACTS_FILE}) not found. Starting with an empty contact list.")
    except json.JSONDecodeError:
        print(f"Error decoding {CONTACTS_FILE}. Starting with an empty contact list.")

def save_contacts():
    with open(CONTACTS_FILE, 'w') as f:
        json.dump(contacts, f, indent=4)
    print(f"Contacts saved to {CONTACTS_FILE}")

def add_contact(nickname, ip_address):
    if not nickname or not ip_address:
        print("Error: Nickname and IP address cannot be empty.")
        return
    try:
        socket.inet_aton(ip_address)
        contacts[nickname] = ip_address
        save_contacts()
        print(f"Contact '{nickname}' added/updated: {ip_address}")
    except socket.error:
        print(f"Error: Invalid IP address format for '{ip_address}'.")


def list_contacts():
    if not contacts:
        print("Contact list is empty.")
        return
    print("\n--- Contacts ---")
    for nickname, ip in contacts.items():
        print(f"- {nickname}: {ip}")
    print("----------------\n")

def get_contact_ip(nickname):
    return contacts.get(nickname)

def create_xmpp_message(to_ip, from_ip, message_body):

    if not all([to_ip, from_ip, message_body]):
        print("Error: Cannot create message with empty fields.")
        return None

    msg_element = ET.Element("message")
    msg_element.set("to", to_ip)
    msg_element.set("from", from_ip)
    msg_element.set("type", "chat")
    msg_element.set("xmlns", "jabber:client")

    body_element = ET.SubElement(msg_element, "body")
    body_element.text = message_body

    return ET.tostring(msg_element, encoding="unicode")

def parse_xmpp_message(xml_string):
    try:
        root = ET.fromstring(xml_string)
       
        namespace_uri = "jabber:client"
        expected_message_tag = f"{{{namespace_uri}}}message"
        expected_body_tag = f"{{{namespace_uri}}}body"

        if root.tag == expected_message_tag:
            from_ip = root.get("from")
           
            body_element = root.find(expected_body_tag)
           
            if body_element is not None:
                message_text = body_element.text
                return from_ip, message_text
            else:
                print(f"Warning: Message (tag: {root.tag}) received with no body element (expected tag: {expected_body_tag}).")
                return from_ip, ""
        else:
            print(f"Warning: Received XML with unexpected root tag: '{root.tag}'. Expected '{expected_message_tag}'.")
            return None, None 
           
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}. Raw string (first 200 chars): '{xml_string[:200]}...'")
        return None, None
    except Exception as e:
        print(f"An unexpected error occurred during XML parsing: {e}")
        return None, None

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def listen_for_messages(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"Listening for messages on {host}:{port}...")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"\n[+] Accepted connection from {client_address[0]}:{client_address[1]}")
            try:
                message_chunks = []
                while True:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    message_chunks.append(chunk)
                    if b"</message>" in chunk:
                        break
               
                if not message_chunks:
                    print(f"[-] No data received from {client_address[0]}. Connection closed.")
                    client_socket.close()
                    continue

                full_message_bytes = b"".join(message_chunks)
                full_message_str = full_message_bytes.decode('utf-8', errors='replace')

                print(f"[<] Received raw: {full_message_str}")
                from_ip, message_text = parse_xmpp_message(full_message_str)

                if from_ip is not None and message_text is not None:
                    sender_nickname = "[Unknown IP]"
                    for nick, ip_addr in contacts.items():
                        if ip_addr == from_ip:
                            sender_nickname = nick
                            break
                    print(f"\n>>> Message from {sender_nickname} ({from_ip}): {message_text}")
                else:
                    print(f"[!] Failed to properly parse message from {client_address[0]}. See logs above. Raw data: {full_message_str}")
               
                print_prompt()

            except ConnectionResetError:
                print(f"[-] Connection reset by {client_address[0]}.")
            except UnicodeDecodeError:
                print(f"[!] Error decoding message from {client_address[0]}. Ensure it's UTF-8 XML.")
            except Exception as e:
                print(f"[!] Error handling message from {client_address[0]}: {e}")
            finally:
                client_socket.close()
    except OSError as e:
        print(f"[!] Error starting listener on {host}:{port}: {e}. Is the port already in use?")
    except Exception as e:
        print(f"[!] Critical listener error: {e}")
    finally:
        server_socket.close()


def send_message(recipient_nickname_or_ip, message_text, sender_ip, target_port):
    recipient_ip = get_contact_ip(recipient_nickname_or_ip)
    if not recipient_ip:
        try:
            socket.inet_aton(recipient_nickname_or_ip)
            recipient_ip = recipient_nickname_or_ip
        except socket.error:
            print(f"Error: Nickname '{recipient_nickname_or_ip}' not found in contacts, and it's not a valid IP.")
            return

    if not sender_ip:
        print("Error: Sender IP (your IP) is not set. Cannot send message.")
        return

    xml_message = create_xmpp_message(to_ip=recipient_ip, from_ip=sender_ip, message_body=message_text)
    if not xml_message:
        print("Failed to create XML message.")
        return

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)
        print(f"\n[>] Attempting to send to {recipient_ip}:{target_port}...")
        client_socket.connect((recipient_ip, target_port))
        client_socket.sendall(xml_message.encode('utf-8'))
        print(f"[>] Message sent to {recipient_nickname_or_ip} ({recipient_ip}).")
    except socket.timeout:
        print(f"[!] Connection to {recipient_ip}:{target_port} timed out.")
    except ConnectionRefusedError:
        print(f"[!] Connection to {recipient_ip}:{target_port} refused. Is the other client listening?")
    except socket.gaierror:
        print(f"[!] Invalid address or hostname: {recipient_ip}")
    except Exception as e:
        print(f"[!] Error sending message to {recipient_ip}: {e}")
    finally:
        if 'client_socket' in locals() and client_socket.fileno() != -1:
            client_socket.close()

def print_prompt():
    print("\n(Cmd: send <nick/IP> <msg> | add <nick> <IP> | contacts | myip | exit) > ", end="")

if __name__ == "__main__":
    MY_IP_ADDRESS = get_my_ip()
    print(f"--- IP Messenger CLI ---")
    print(f"Your IP address appears to be: {MY_IP_ADDRESS}")
    print(f"Ensure this IP is reachable by other clients on your network.")
    print(f"Default listening port is {DEFAULT_PORT}. You can change DEFAULT_PORT in the script.")
    print("Type 'exit' to quit.")

    load_contacts()

    listener_thread = threading.Thread(target=listen_for_messages, args=("0.0.0.0", DEFAULT_PORT), daemon=True)
    listener_thread.start()

    time.sleep(0.5)

    while True:
        print_prompt()
        try:
            command_input = input()
            if not command_input:
                continue

            parts = command_input.split(maxsplit=2)
            cmd = parts[0].lower()

            if cmd == "exit":
                print("Exiting IP Messenger...")
                save_contacts()
                break
            elif cmd == "send":
                if len(parts) < 3:
                    print("Usage: send <nickname_or_IP> <message_text>")
                else:
                    recipient = parts[1]
                    message = parts[2]
                    send_message(recipient, message, MY_IP_ADDRESS, DEFAULT_PORT)
            elif cmd == "add":
                if len(parts) < 3:
                    print("Usage: add <nickname> <ip_address>")
                else:
                    nickname = parts[1]
                    ip = parts[2]
                    add_contact(nickname, ip)
            elif cmd == "contacts":
                list_contacts()
            elif cmd == "myip":
                print(f"Your current IP address is: {MY_IP_ADDRESS}")
                print(f"Listening on port: {DEFAULT_PORT}")
            else:
                print(f"Unknown command: '{cmd}'")

        except KeyboardInterrupt:
            print("\nExiting IP Messenger (Ctrl+C)...")
            save_contacts()
            break
        except EOFError:
            print("\nExiting IP Messenger (EOF)...")
            save_contacts()
            break
        except Exception as e:
            print(f"An error occurred in the main loop: {e}")
