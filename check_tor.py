# check_tor.py
from stem.control import Controller

TOR_CONTROL_PORT = 9051

def main():
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate()  # cookie auth
            print("[+] Connected to Tor")
            print("[+] Tor version:", controller.get_version())

            # Create ephemeral hidden service mapping local port 8000 → onion 80
            hidden_service = controller.create_ephemeral_hidden_service({80: 8000}, await_publication=True)
            onion_address = f"http://{hidden_service.service_id}.onion"
            print("[+] Ephemeral Onion service created:", onion_address)

            # Save to file
            with open("onion_address.txt", "w") as f:
                f.write(onion_address)

    except Exception as e:
        print(f"[-] Failed to connect to Tor: {e}")

if __name__ == "__main__":
    main()
