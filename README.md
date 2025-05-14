# network-final-project
# 💬 IP Messenger

**IP Messenger** is a modern, TCP/IP-based chat application built with Python’s `customtkinter` GUI framework. It enables local or LAN-based real-time messaging using a contact list and per-user chat history. Messages are encoded in a simple XML-like format similar to XMPP.

---

## 📦 Features

- 📜 **CustomTkinter UI** with a responsive sidebar and chat pane
- 🧑‍🤝‍🧑 **Contact management**: add, remove, and store contacts by nickname/IP
- 💬 **Real-time messaging** over sockets (TCP)
- 🗂️ **Chat history** stored per contact (in memory)
- 🧾 **XMPP-like message formatting and parsing**

---

## 🚀 Getting Started

### 📋 Requirements

- Python 3.8+
- `customtkinter`

Install dependencies:
```bash
pip install customtkinter
```

---

### 🏁 Running the App

1. **Set your IP address**:
   The application auto-detects your IP. You can override it manually in the script if needed.

2. **Start the app**:
```bash
python clientUi.py
```

3. **Add contacts**:
   Use the `Add Contact` button to add a contact by nickname and IP address.
   Adding the first contact will create a json file `contacts.json`, where the contacts will be stored.

5. **Start chatting**:
   Click a contact to open the chat. Messages will be sent over TCP.
   Right-click a contact to deselect.
   CLick the Remove contact button on a selected contact or if not selected, the program will prompt you to show the contact you want to remove manually.


## 🛠️ Command Line Client

### 🏁 Running the Client

```bash
python clientUi.py
```

**Follow the commands**
  Follow the commands that will appear in the command line.
  Overall the functionality is similar to the UI client.
  Try also connecting the command line client to the UI client.

## ⚙️ Customization

- You can change the listening port by modifying the `PORT` constant.

---




## 🧑‍💻 Authors

Created by **Edgar, Eduard and Albert** — computer science students passionate about networking and UI design.
