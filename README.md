# khelp - Ultimate Kali Linux Post-Install Helper

`khelp` is a helper script designed for fresh Kali Linux installations. It automates the process of updating the system, installing useful packages, useful tools and configuring services to save time and effort. This script also includes features to spoof the hostname and MAC address for enhanced privacy. This script was tested on Kali Linux - Gnome Desktop (bare metal) and inside VMware.


![Fedora 41 Workstation - fastfetch](https://github.com/Obi83/khelp/blob/main/media/fastfetch.png)


### Features
- Full update/upgrade cycle
- Tool installation
- Installing essential packages
- Hostname changer
- MAC address changer



# Detailed Steps


![Fedora 41 Workstation - khelp](https://github.com/Obi83/khelp/blob/main/media/khelp.png)


### 1. Full Update Cycle
The script begins by ensuring your Kali Linux system is fully updated and cleaned. This step includes:

- **Updating System Packages**: Fetches and installs the latest updates for all installed packages.
- **Removing Unnecessary Packages**: Removes packages that are no longer needed.
- **Cleaning Up Package Cache**: Frees up disk space by removing cached package files.


### 2. Tool Installation
This step focuses on installing essential tools and utilities:

- **Installing Essential Packages**: Installs a list of useful tools and utilities, including:
    - `kali-linux-large`: A comprehensive package of tools for Kali Linux.
    - `kali-tools-windows-resources`: Tools useful for Windows resources.
    - `terminator`: A terminal emulator with advanced features.
    - `bpytop`: A resource monitor.
    - `htop`: An interactive process viewer.
    - `shellcheck`: A static analysis tool for shell scripts.
    - `seclists`: A collection of multiple types of lists used during security assessments.
    - `inxi`: A system information tool.
    - `ufw`: A user-friendly firewall.
    - `tor`: Anonymity network client.
    - `fastfetch`: A fast system information tool.
    - `guake`: A dropdown terminal.



### 3. Hostname Changer
To enhance privacy, the script includes a service that generates a random hostname:

- **Generating a Random Hostname**: Creates an 8-character hostname from random syllables.
- **Setting the New Hostname**: Uses `hostnamectl` to set the new hostname.
- **Updating `/etc/hosts`**: Updates the hosts file to reflect the new hostname.
- **Systemd Service**: Ensures the hostname is set at boot.


### 4. MAC Address Changer
For additional privacy, the script includes a service that spoofs the MAC address:

- **Determining the Primary Network Interface**: Identifies the primary network interface.
- **Generating a Random MAC Address**: Generates a random MAC address.
- **Changing the MAC Address**: Sets the new MAC address.
- **Displaying the New MAC Address**: Confirms the change by displaying the new MAC address.
- **Systemd Service**: Ensures the MAC address is changed at boot.


![Fedora 41 Workstation - spoofer](https://github.com/Obi83/khelp/blob/main/media/hogen-mspoo1.png)
![Fedora 41 Workstation - spoofer](https://github.com/Obi83/khelp/blob/main/media/hogen-mspoo2.png)


# Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/Obi83/khelp.git
    cd khelp
    ```

2. Make the `khelp.sh` script executable:
    ```bash
    sudo chmod +x khelp.sh
    ```

3. Execute the `khelp.sh` script as root:
    ```bash
    sudo ./khelp.sh
    ```

# Usage
Run the `khelp.sh` script to perform the following tasks:

- Update and clean the system
- Install essential packages and useful helper tools
- Set up and enable hostname generator service
- Set up and enable MAC address spoofing service

# References
This script was created by Obi83 with assistance from AI. For a full list of references and sources that inspired parts of this script, please see the [REFERENCES.md](REFERENCES.md) file.

# License
This project is licensed under the MIT License. See the [LICENSE](LICENSE.txt) file for details.
