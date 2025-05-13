import customtkinter as ctk
from tkinter import messagebox
from tkinter import Menu
import socket
import threading
import xml.etree.ElementTree as ET
import time
import json
import queue


DEFAULT_PORT = 5555
CONTACTS_FILE = "contacts.json"
MY_IP_ADDRESS = ""

ctk.set_appearance_mode("Dark")  
ctk.set_default_color_theme("blue")  

contacts = {}  
message_update_queue = queue.Queue()

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
    return contacts

def save_contacts():
    try:
        with open(CONTACTS_FILE, 'w') as f:
            json.dump(contacts, f, indent=4)
        print(f"Contacts saved to {CONTACTS_FILE}")
    except Exception as e:
        print(f"Error saving contacts: {e}")


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
                print(f"Warning: Message (tag: {root.tag}) received with no body element.")
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

class ModernMessengerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(f"Modern IP Messenger - My IP: {MY_IP_ADDRESS} Port: {DEFAULT_PORT}")
        self.geometry("800x600")
        self.minsize(600, 400)

        self.current_chat_partner_nick = None
        self.chat_history = {}
        self.contact_buttons = {}
        self.selected_contact_button_widget = None

        temp_btn = ctk.CTkButton(self)
        self.contact_default_fg_color = temp_btn.cget("fg_color")
        self.contact_highlight_color = temp_btn.cget("hover_color")
        temp_btn.destroy()


        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)    

        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(1, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="Contacts", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
       
        self.contacts_scrollable_frame = ctk.CTkScrollableFrame(self.sidebar_frame, label_text="")
        self.contacts_scrollable_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.contacts_scrollable_frame.grid_columnconfigure(0, weight=1)
        self.contacts_scrollable_frame.bind("<Button-3>", self.handle_contacts_area_right_click, add="+")


        self.add_contact_button = ctk.CTkButton(self.sidebar_frame, text="Add Contact", command=self.add_contact_dialog)
        self.add_contact_button.grid(row=2, column=0, padx=20, pady=10)

        self.remove_contact_button = ctk.CTkButton(self.sidebar_frame, text="Remove Contact", command=self.remove_contact_dialog)
        self.remove_contact_button.grid(row=3, column=0, padx=20, pady=10)
       
        self.refresh_contacts_button = ctk.CTkButton(self.sidebar_frame, text="Refresh Contacts", command=self.refresh_contacts_ui_list)
        self.refresh_contacts_button.grid(row=4, column=0, padx=20, pady=(0,20))


        self.chat_area_frame = ctk.CTkFrame(self, corner_radius=0)
        self.chat_area_frame.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.chat_area_frame.grid_rowconfigure(1, weight=1)
        self.chat_area_frame.grid_columnconfigure(0, weight=1)

        self.chat_partner_label = ctk.CTkLabel(self.chat_area_frame, text="Select a contact to chat", font=ctk.CTkFont(size=16, weight="bold"))
        self.chat_partner_label.grid(row=0, column=0, padx=20, pady=(10,5), sticky="w")

        self.chat_display_textbox = ctk.CTkTextbox(self.chat_area_frame, state=ctk.DISABLED, wrap="word", corner_radius=5, border_spacing=5)
        self.chat_display_textbox.grid(row=1, column=0, padx=10, pady=(0,10), sticky="nsew")

        self.input_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.input_frame.grid(row=1, column=1, sticky="sew", padx=10, pady=(0,10))
        self.input_frame.grid_columnconfigure(0, weight=1)

        self.message_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Type your message...", height=40)
        self.message_entry.grid(row=0, column=0, padx=(0,10), pady=0, sticky="ew")
        self.message_entry.bind("<Return>", self.send_message_ui_event_handler)

        self.send_button = ctk.CTkButton(self.input_frame, text="Send", command=self.send_message_ui_event_handler, width=80, height=40)
        self.send_button.grid(row=0, column=1, pady=0, sticky="e")

        self.refresh_contacts_ui_list()

        self.listener_thread = threading.Thread(target=self.listen_for_messages_network_thread, args=("0.0.0.0", DEFAULT_PORT), daemon=True)
        self.listener_thread.start()

        self.after(100, self.process_ui_update_queue)

        self.protocol("WM_DELETE_WINDOW", self.on_app_closing)

    def on_app_closing(self):
        if messagebox.askokcancel("Quit IP Messenger?", "Do you want to quit?"):
            save_contacts()
            self.destroy()

    def add_contact_dialog(self):
        nickname_dialog = ctk.CTkInputDialog(text="Enter contact's nickname:", title="Add Contact")
        nickname = nickname_dialog.get_input()
       
        if not nickname:
            return
        if nickname in contacts:
            messagebox.showwarning("Add Contact", f"Nickname '{nickname}' already exists.", parent=self)
            return
           
        ip_dialog = ctk.CTkInputDialog(text=f"Enter IP address for {nickname}:", title="Add Contact")
        ip_address = ip_dialog.get_input()

        if not ip_address:
            return

        try:
            socket.inet_aton(ip_address)
            contacts[nickname] = ip_address
            if nickname not in self.chat_history:
                self.chat_history[nickname] = ""
            save_contacts()
            self.refresh_contacts_ui_list()
            messagebox.showinfo("Add Contact", f"Contact '{nickname}' added successfully.", parent=self)
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address format.", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Error adding contact: {e}", parent=self)

    def remove_contact_dialog(self):
        nickname_to_remove = None
       
        if self.current_chat_partner_nick:
            nickname_to_remove = self.current_chat_partner_nick
            if not messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove the selected contact '{nickname_to_remove}'?", parent=self):
                return
        else:
            if not contacts:
                messagebox.showinfo("Remove Contact", "Contact list is empty.", parent=self)
                return
           
            input_dialog = ctk.CTkInputDialog(text="Enter nickname of contact to remove:", title="Remove Contact")
            nickname_to_remove = input_dialog.get_input()

            if not nickname_to_remove:
                return

            if nickname_to_remove not in contacts:
                messagebox.showerror("Remove Contact", f"Contact '{nickname_to_remove}' not found.", parent=self)
                return
           
            if not messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove '{nickname_to_remove}' from your contacts?", parent=self):
                return
       
        if nickname_to_remove:
            try:
                del contacts[nickname_to_remove]
                if nickname_to_remove in self.chat_history:
                    del self.chat_history[nickname_to_remove]
               
                save_contacts()
               
                if self.current_chat_partner_nick == nickname_to_remove:
                    self.deselect_current_contact()

                self.refresh_contacts_ui_list()
                messagebox.showinfo("Remove Contact", f"Contact '{nickname_to_remove}' removed.", parent=self)
           
            except Exception as e:
                messagebox.showerror("Remove Contact", f"Error removing contact: {e}", parent=self)

    def handle_contacts_area_right_click(self, event):
        if self.current_chat_partner_nick:
            self.deselect_current_contact()


    def deselect_current_contact(self):
        if self.selected_contact_button_widget:
            self.selected_contact_button_widget.configure(fg_color=self.contact_default_fg_color)
       
        self.current_chat_partner_nick = None
        self.selected_contact_button_widget = None
        self.chat_partner_label.configure(text="Select a contact to chat")
        self._update_chat_display_content_ui("")


    def refresh_contacts_ui_list(self):
        for widget in self.contacts_scrollable_frame.winfo_children():
            widget.destroy()
        self.contact_buttons.clear()

        sorted_nicknames = sorted(contacts.keys())
       
        previously_selected_nick = self.current_chat_partner_nick
        self.selected_contact_button_widget = None

        for nickname in sorted_nicknames:
            if nickname not in self.chat_history:
                 self.chat_history[nickname] = ""

            contact_btn = ctk.CTkButton(
                self.contacts_scrollable_frame,
                text=nickname,
                command=lambda n=nickname: self.on_contact_selected(n),
                anchor="w",
                fg_color=self.contact_default_fg_color
            )
            contact_btn.bind("<Button-3>", self.handle_contacts_area_right_click, add="+")
            contact_btn.grid(sticky="ew", padx=5, pady=2)
            self.contact_buttons[nickname] = contact_btn

            if nickname == previously_selected_nick:
                contact_btn.configure(fg_color=self.contact_highlight_color)
                self.selected_contact_button_widget = contact_btn
       
        if previously_selected_nick and previously_selected_nick not in self.contact_buttons:
            self.deselect_current_contact()
        elif not self.selected_contact_button_widget and self.current_chat_partner_nick:
             self.deselect_current_contact()


    def on_contact_selected(self, selected_nickname):
        if selected_nickname not in contacts:
            print(f"Error: Selected nickname '{selected_nickname}' not in contacts.")
            self.refresh_contacts_ui_list()
            return

        if self.current_chat_partner_nick == selected_nickname and self.selected_contact_button_widget:
             if self.selected_contact_button_widget.cget("fg_color") == self.contact_highlight_color:
                return


        if self.selected_contact_button_widget is not None:
            self.selected_contact_button_widget.configure(fg_color=self.contact_default_fg_color)

        self.current_chat_partner_nick = selected_nickname
        newly_selected_button = self.contact_buttons.get(selected_nickname)
       
        if newly_selected_button:
             newly_selected_button.configure(fg_color=self.contact_highlight_color)
             self.selected_contact_button_widget = newly_selected_button
             btn_text = newly_selected_button.cget("text")
             if btn_text.endswith(" (*)"):
                 newly_selected_button.configure(text=selected_nickname)
        else:
            self.selected_contact_button_widget = None


        ip_addr = contacts.get(self.current_chat_partner_nick, "N/A")
        self.chat_partner_label.configure(text=f"Chat with: {self.current_chat_partner_nick} ({ip_addr})")
       
        history = self.chat_history.get(self.current_chat_partner_nick, "")
        self._update_chat_display_content_ui(history)


    def _update_chat_display_content_ui(self, content):
        self.chat_display_textbox.configure(state=ctk.NORMAL)
        self.chat_display_textbox.delete("1.0", ctk.END)
        self.chat_display_textbox.insert(ctk.END, content)
        self.chat_display_textbox.see(ctk.END)
        self.chat_display_textbox.configure(state=ctk.DISABLED)

    def _append_message_to_chat_ui(self, message_line, partner_identifier):
        if partner_identifier not in self.chat_history:
            self.chat_history[partner_identifier] = ""
       
        self.chat_history[partner_identifier] += message_line + "\n"

        if self.current_chat_partner_nick == partner_identifier:
            self.chat_display_textbox.configure(state=ctk.NORMAL)
            self.chat_display_textbox.insert(ctk.END, message_line + "\n")
            self.chat_display_textbox.see(ctk.END)
            self.chat_display_textbox.configure(state=ctk.DISABLED)
        else:
            if partner_identifier in self.contact_buttons:
                btn = self.contact_buttons[partner_identifier]
                current_btn_text = btn.cget("text")
                base_nickname = current_btn_text.replace(" (*)", "")
                if base_nickname == partner_identifier and not current_btn_text.endswith(" (*)"):
                    btn.configure(text=f"{partner_identifier} (*)")

    def send_message_ui_event_handler(self, event=None):
        message_text = self.message_entry.get()
        if not message_text.strip():
            messagebox.showwarning("Send Message", "Cannot send an empty message.", parent=self)
            return
        if not self.current_chat_partner_nick:
            messagebox.showwarning("Send Message", "Please select a contact to send a message to.", parent=self)
            return

        recipient_ip = get_contact_ip(self.current_chat_partner_nick)
        if not recipient_ip:
            messagebox.showerror("Send Error", f"Could not find IP for {self.current_chat_partner_nick}.", parent=self)
            return

        xml_message = create_xmpp_message(to_ip=recipient_ip, from_ip=MY_IP_ADDRESS, message_body=message_text)
        if not xml_message:
            messagebox.showerror("Send Error", "Failed to create XML message.", parent=self)
            return

        try:
            threading.Thread(target=self._send_message_network_task, args=(recipient_ip, xml_message, message_text), daemon=True).start()
        except Exception as e:
            messagebox.showerror("Send Error", f"Error initiating send: {e}", parent=self)

    def _send_message_network_task(self, recipient_ip, xml_message, original_message_text):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect((recipient_ip, DEFAULT_PORT))
            client_socket.sendall(xml_message.encode('utf-8'))
            client_socket.close()
           
            message_update_queue.put(("Me", MY_IP_ADDRESS, original_message_text, self.current_chat_partner_nick, True))
            self.message_entry.after(0, lambda: self.message_entry.delete(0, ctk.END))
        except socket.timeout:
            message_update_queue.put(("Error", None, f"Connection to {self.current_chat_partner_nick} ({recipient_ip}) timed out.", self.current_chat_partner_nick, False))
        except ConnectionRefusedError:
            message_update_queue.put(("Error", None, f"Connection to {self.current_chat_partner_nick} ({recipient_ip}) refused.", self.current_chat_partner_nick, False))
        except Exception as e:
            message_update_queue.put(("Error", None, f"Error sending message: {e}", self.current_chat_partner_nick, False))


    def listen_for_messages_network_thread(self, host, port):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind((host, port))
            server_socket.listen(5)
            print(f"UI Listener (CustomTkinter) started on {host}:{port}")

            while True:
                try:
                    client_socket, client_address = server_socket.accept()
                    print(f"UI (CTk): Accepted connection from {client_address[0]}:{client_address[1]}")
                   
                    message_chunks = []
                    client_socket.settimeout(5.0)
                    try:
                        while True:
                            chunk = client_socket.recv(4096)
                            if not chunk: break
                            message_chunks.append(chunk)
                            if b"</message>" in chunk: break
                    except socket.timeout:
                        print("UI (CTk): Socket recv timeout while reading message chunks.")
                   
                    if not message_chunks:
                        client_socket.close()
                        continue

                    full_message_bytes = b"".join(message_chunks)
                    full_message_str = full_message_bytes.decode('utf-8', errors='replace')
                   
                    from_ip, message_text = parse_xmpp_message(full_message_str)

                    if from_ip and message_text is not None:
                        sender_display_name = from_ip
                        chat_history_key = from_ip

                        for nick, ip_addr in contacts.items():
                            if ip_addr == from_ip:
                                sender_display_name = nick
                                chat_history_key = nick
                                break
                       
                        message_update_queue.put((sender_display_name, from_ip, message_text, chat_history_key, False))
                    else:
                        print(f"UI (CTk): Could not parse message from {client_address[0]}. Raw: {full_message_str[:200]}")
                    client_socket.close()
                except ConnectionResetError:
                    print(f"UI Listener (CTk): Connection reset by peer.")
                except Exception as e:
                    print(f"UI Listener (CTk): Error in connection handling loop: {e}")
        except OSError as e:
             print(f"UI Listener (CTk): Error starting listener on {host}:{port}: {e}")
             self.after(10, lambda: messagebox.showerror("Listener Error",
                                                  f"Could not start listening on port {port}.\nIs another instance running or port in use?\n\nError: {e}",
                                                  parent=self))
        except Exception as e:
            print(f"UI Listener (CTk): Critical listener thread error: {e}")
        finally:
            if server_socket:
                server_socket.close()
            print("UI Listener (CTk) thread stopped.")

    def process_ui_update_queue(self):
        try:
            while not message_update_queue.empty():
                sender_display_name, from_ip, message_text, chat_history_key, is_self_sent = message_update_queue.get_nowait()
               
                if sender_display_name == "Error":
                    self._append_message_to_chat_ui(f"System Error: {message_text}", chat_history_key)
                elif is_self_sent:
                    self._append_message_to_chat_ui(f"Me: {message_text}", chat_history_key)
                else:
                    self._append_message_to_chat_ui(f"{sender_display_name}: {message_text}", chat_history_key)

        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error processing UI update queue: {e}")
       
        self.after(200, self.process_ui_update_queue)


if __name__ == "__main__":
    MY_IP_ADDRESS = get_my_ip()
    contacts = load_contacts()

    app = ModernMessengerApp()
    app.mainloop()
