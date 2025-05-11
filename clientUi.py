import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext, Listbox, Menu
import socket
import threading
import xml.etree.ElementTree as ET
import time
import json
import queue  # For thread-safe UI updates

# --- Configuration (same as CLI) ---
DEFAULT_PORT = 5555
CONTACTS_FILE = "contacts.json"
MY_IP_ADDRESS = ""

# --- Contact Management (reused and adapted) ---
contacts = {}  # In-memory store: {"nickname": "ip_address"}
message_queues = {}  # For UI updates from network thread: {"nickname_or_ip": queue.Queue()}


def load_contacts():
    global contacts
    try:
        with open(CONTACTS_FILE, 'r') as f:
            contacts = json.load(f)
        # Initialize message queues for existing contacts
        for nickname in contacts:
            if nickname not in message_queues:
                message_queues[nickname] = queue.Queue()
        print(f"Contacts loaded from {CONTACTS_FILE}")
    except FileNotFoundError:
        print(f"Contacts file ({CONTACTS_FILE}) not found. Starting with an empty contact list.")
    except json.JSONDecodeError:
        print(f"Error decoding {CONTACTS_FILE}. Starting with an empty contact list.")
    return contacts


def save_contacts():
    with open(CONTACTS_FILE, 'w') as f:
        json.dump(contacts, f, indent=4)
    print(f"Contacts saved to {CONTACTS_FILE}")


def get_contact_ip(nickname):
    return contacts.get(nickname)


# --- Message Formatting and Parsing (reused from CLI) ---
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
                print(f"Warning: Message (tag: {root.tag}) received with no body element.")
                return from_ip, ""
        else:
            print(f"Warning: Received XML with unexpected root tag: '{root.tag}'.")
            return None, None
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}. Raw string (first 200 chars): '{xml_string[:200]}...'")
        return None, None
    except Exception as e:
        print(f"An unexpected error occurred during XML parsing: {e}")
        return None, None


# --- Networking (adapted for UI) ---
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


class MessengerApp:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title(f"IP Messenger UI - My IP: {MY_IP_ADDRESS} Port: {DEFAULT_PORT}")
        self.root.geometry("700x500")

        self.current_chat_partner_nick = None  # Nickname of the currently selected chat partner
        self.chat_history = {}  # {"nickname": "chat string"}

        # --- UI Elements ---
        # Main frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Contacts List (Left Pane)
        contacts_frame = tk.Frame(main_frame, width=150)
        contacts_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        contacts_frame.pack_propagate(False)  # Prevent resizing

        tk.Label(contacts_frame, text="Contacts", font=("Arial", 12, "bold")).pack(pady=(0, 5))
        self.contacts_listbox = Listbox(contacts_frame, exportselection=False, selectmode=tk.SINGLE)
        self.contacts_listbox.pack(fill=tk.BOTH, expand=True)
        self.contacts_listbox.bind('<<ListboxSelect>>', self.on_contact_select)

        # Chat Area (Right Pane)
        chat_frame = tk.Frame(main_frame)
        chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.chat_display_partner_label = tk.Label(chat_frame, text="Select a contact to chat",
                                                   font=("Arial", 12, "bold"))
        self.chat_display_partner_label.pack(pady=(0, 5))

        self.chat_display = scrolledtext.ScrolledText(chat_frame, state=tk.DISABLED, wrap=tk.WORD, height=15)
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Message Input Area
        input_frame = tk.Frame(chat_frame)
        input_frame.pack(fill=tk.X)

        self.message_entry = tk.Entry(input_frame, font=("Arial", 11))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        self.message_entry.bind("<Return>", self.send_message_ui_event)  # Send on Enter

        self.send_button = tk.Button(input_frame, text="Send", command=self.send_message_ui_event, width=10)
        self.send_button.pack(side=tk.RIGHT, padx=(5, 0))

        # Status Bar
        self.status_bar = tk.Label(self.root, text=f"My IP: {MY_IP_ADDRESS} | Listening on Port: {DEFAULT_PORT}", bd=1,
                                   relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # --- Menu ---
        menubar = Menu(self.root)
        self.root.config(menu=menubar)

        contacts_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Contacts", menu=contacts_menu)
        contacts_menu.add_command(label="Add Contact", command=self.add_contact_dialog)
        contacts_menu.add_command(label="Refresh List", command=self.refresh_contacts_listbox)
        contacts_menu.add_separator()
        contacts_menu.add_command(label="Exit", command=self.on_closing)

        # --- Load initial data ---
        self.refresh_contacts_listbox()

        # --- Start listening for messages ---
        self.listener_thread = threading.Thread(target=self.listen_for_messages_thread, args=("0.0.0.0", DEFAULT_PORT),
                                                daemon=True)
        self.listener_thread.start()

        # --- Start UI update loop for messages ---
        self.root.after(100, self.process_message_queues)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit IP Messenger?"):
            save_contacts()  # Save contacts before closing
            self.root.destroy()

    def add_contact_dialog(self):
        nickname = simpledialog.askstring("Add Contact", "Enter contact's nickname:", parent=self.root)
        if not nickname:
            return
        if nickname in contacts:
            messagebox.showwarning("Add Contact", f"Nickname '{nickname}' already exists.", parent=self.root)
            return

        ip_address = simpledialog.askstring("Add Contact", f"Enter IP address for {nickname}:", parent=self.root)
        if not ip_address:
            return

        try:
            socket.inet_aton(ip_address)  # Validate IP
            contacts[nickname] = ip_address
            if nickname not in message_queues:  # Add message queue for new contact
                message_queues[nickname] = queue.Queue()
            if nickname not in self.chat_history:  # Initialize chat history for new contact
                self.chat_history[nickname] = ""
            save_contacts()
            self.refresh_contacts_listbox()
            messagebox.showinfo("Add Contact", f"Contact '{nickname}' added.", parent=self.root)
        except socket.error:
            messagebox.showerror("Add Contact", "Invalid IP address format.", parent=self.root)
        except Exception as e:
            messagebox.showerror("Add Contact", f"Error adding contact: {e}", parent=self.root)

    def refresh_contacts_listbox(self):
        self.contacts_listbox.delete(0, tk.END)
        sorted_nicknames = sorted(contacts.keys())
        for nickname in sorted_nicknames:
            self.contacts_listbox.insert(tk.END, nickname)
            if nickname not in self.chat_history:
                self.chat_history[nickname] = ""  # Initialize chat history if not present

    def on_contact_select(self, event=None):
        try:
            selected_indices = self.contacts_listbox.curselection()
            if not selected_indices:
                self.current_chat_partner_nick = None
                self.chat_display_partner_label.config(text="Select a contact to chat")
                self._update_chat_display_content("")  # Clear chat display
                return

            selected_index = selected_indices[0]
            self.current_chat_partner_nick = self.contacts_listbox.get(selected_index)

            self.chat_display_partner_label.config(
                text=f"Chat with: {self.current_chat_partner_nick} ({contacts.get(self.current_chat_partner_nick, 'N/A')})")

            # Load and display chat history for the selected contact
            history = self.chat_history.get(self.current_chat_partner_nick, "")
            self._update_chat_display_content(history)

        except Exception as e:
            print(f"Error in on_contact_select: {e}")
            self.current_chat_partner_nick = None
            self.chat_display_partner_label.config(text="Error selecting contact")
            self._update_chat_display_content("")

    def _update_chat_display_content(self, content):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.insert(tk.END, content)
        self.chat_display.see(tk.END)  # Scroll to the bottom
        self.chat_display.config(state=tk.DISABLED)

    def append_to_chat_display(self, message_line, partner_nick_or_ip):
        """Appends a line to the chat display and updates chat history."""
        if partner_nick_or_ip not in self.chat_history:
            self.chat_history[partner_nick_or_ip] = ""

        self.chat_history[partner_nick_or_ip] += message_line + "\n"

        # If the message is for the currently selected chat partner, update the display
        if self.current_chat_partner_nick == partner_nick_or_ip:
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, message_line + "\n")
            self.chat_display.see(tk.END)
            self.chat_display.config(state=tk.DISABLED)

        # Potentially add a visual notification for unread messages from other contacts
        # For simplicity, this is not implemented here.

    def send_message_ui_event(self, event=None):  # event is passed by <Return> binding
        message_text = self.message_entry.get()
        if not message_text:
            messagebox.showwarning("Send Message", "Cannot send an empty message.", parent=self.root)
            return
        if not self.current_chat_partner_nick:
            messagebox.showwarning("Send Message", "Please select a contact to send a message to.", parent=self.root)
            return

        recipient_ip = get_contact_ip(self.current_chat_partner_nick)
        if not recipient_ip:
            messagebox.showerror("Send Message", f"Could not find IP for {self.current_chat_partner_nick}.",
                                 parent=self.root)
            return

        xml_message = create_xmpp_message(to_ip=recipient_ip, from_ip=MY_IP_ADDRESS, message_body=message_text)
        if not xml_message:
            messagebox.showerror("Send Error", "Failed to create XML message.", parent=self.root)
            return

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5)  # 5 seconds timeout
            client_socket.connect((recipient_ip, DEFAULT_PORT))
            client_socket.sendall(xml_message.encode('utf-8'))
            client_socket.close()

            # Display sent message
            self.append_to_chat_display(f"Me: {message_text}", self.current_chat_partner_nick)
            self.message_entry.delete(0, tk.END)  # Clear input field

        except socket.timeout:
            messagebox.showerror("Send Error",
                                 f"Connection to {self.current_chat_partner_nick} ({recipient_ip}) timed out.",
                                 parent=self.root)
        except ConnectionRefusedError:
            messagebox.showerror("Send Error",
                                 f"Connection to {self.current_chat_partner_nick} ({recipient_ip}) refused. Is the other client online and listening?",
                                 parent=self.root)
        except Exception as e:
            messagebox.showerror("Send Error", f"Error sending message: {e}", parent=self.root)

    def listen_for_messages_thread(self, host, port):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind((host, port))
            server_socket.listen(5)
            print(f"UI Listener started on {host}:{port}")

            while True:  # Should have a proper way to stop this thread on app close
                try:
                    client_socket, client_address = server_socket.accept()
                    print(f"UI: Accepted connection from {client_address[0]}:{client_address[1]}")

                    message_chunks = []
                    while True:
                        chunk = client_socket.recv(4096)
                        if not chunk: break
                        message_chunks.append(chunk)
                        if b"</message>" in chunk: break  # Basic boundary check

                    if not message_chunks:
                        client_socket.close()
                        continue

                    full_message_bytes = b"".join(message_chunks)
                    full_message_str = full_message_bytes.decode('utf-8', errors='replace')

                    from_ip, message_text = parse_xmpp_message(full_message_str)

                    if from_ip and message_text is not None:
                        sender_nickname = from_ip  # Default to IP if nickname not found
                        for nick, ip_addr in contacts.items():
                            if ip_addr == from_ip:
                                sender_nickname = nick
                                break

                        # Use queue to pass message to main thread for UI update
                        if sender_nickname not in message_queues:
                            message_queues[sender_nickname] = queue.Queue()  # Create if new sender
                        message_queues[sender_nickname].put((sender_nickname, from_ip, message_text))
                    else:
                        print(f"UI: Could not parse message from {client_address[0]}. Raw: {full_message_str}")
                    client_socket.close()
                except ConnectionResetError:
                    print(f"UI Listener: Connection reset by peer.")  # Common if other client closes abruptly
                except Exception as e:
                    print(f"UI Listener: Error in connection handling loop: {e}")
                    # Avoid crashing the listener thread for individual connection errors
        except OSError as e:
            print(f"UI Listener: Error starting listener on {host}:{port}: {e}")
            # This is a critical error, often "address already in use"
            # Consider notifying the user via the UI if possible, e.g. using messagebox after root is initialized
            self.root.after(0, lambda: messagebox.showerror("Listener Error",
                                                            f"Could not start listening on port {port}.\nIs another instance running or port in use?\n\nError: {e}",
                                                            parent=self.root))
        except Exception as e:
            print(f"UI Listener: Critical listener thread error: {e}")
        finally:
            server_socket.close()
            print("UI Listener thread stopped.")

    def process_message_queues(self):
        """Processes messages from the queues and updates the UI."""
        for nickname_key, q in message_queues.items():
            try:
                while not q.empty():
                    sender_nickname, from_ip, message_text = q.get_nowait()
                    display_name = sender_nickname if sender_nickname != from_ip else from_ip
                    self.append_to_chat_display(f"{display_name}: {message_text}", sender_nickname)

                    # If message is from someone not currently selected, maybe add a notification
                    if self.current_chat_partner_nick != sender_nickname:
                        # Find index of sender_nickname in listbox
                        try:
                            idx = list(self.contacts_listbox.get(0, tk.END)).index(sender_nickname)
                            current_text = self.contacts_listbox.get(idx)
                            if not current_text.endswith(" (*)"):  # Avoid multiple asterisks
                                self.contacts_listbox.delete(idx)
                                self.contacts_listbox.insert(idx, f"{sender_nickname} (*)")
                        except ValueError:
                            # Nickname not in listbox (e.g. direct IP message from unknown sender)
                            # We could add them dynamically or just show message from IP
                            pass


            except queue.Empty:
                pass  # No messages for this contact
            except Exception as e:
                print(f"Error processing message queue for {nickname_key}: {e}")

        self.root.after(200, self.process_message_queues)  # Check queues periodically


if __name__ == "__main__":
    MY_IP_ADDRESS = get_my_ip()
    contacts = load_contacts()  # Load contacts globally

    root = tk.Tk()
    app = MessengerApp(root)
    root.mainloop()