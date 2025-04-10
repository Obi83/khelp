# Dokumentation des KHelp-Skripts


### **Übersicht**

Das **KHelp-Skript** ist ein vielseitiges und umfassendes Bash-Skript, das verschiedene Aufgaben zur **Systemeinrichtung**, **Netzwerksicherheit** und **Systemwartung** automatisiert. Es vereint mehrere Funktionen, um Firewalls, Proxys, Überwachungstools und sichere Webserver-Konfigurationen mühelos einzurichten. Ziel des Skripts ist es, eine **sichere**, **stabile** und **effiziente Systemumgebung** zu schaffen – ohne dass Benutzer manuelle Eingriffe vornehmen müssen.

**Hinweise**:  
- Dieses Skript wurde **ursprünglich für Kali Linux** entwickelt, eine auf Sicherheit spezialisierte Linux-Distribution.  
- Es ist **nur für Distributionen geeignet, die den Paketmanager `apt` verwenden**, wie Kali Linux, Debian, Ubuntu oder deren Derivate. Andere Distributionen werden nicht unterstützt.  


------------------------------------------------------------------
 

# 1. - **Firewall-Konfiguration**
###

Das Skript richtet zwei Firewall-Systeme ein: **UFW** (Uncomplicated Firewall) und **iptables**. Beide Systeme dienen als Schutzmechanismen, um das System vor unbefugtem Zugriff zu schützen. Diese Firewalls regeln den Datenverkehr (eingehend und ausgehend) und stellen sicher, dass nur autorisierte Verbindungen zugelassen werden.

Das Skript richtet sowohl UFW (Uncomplicated Firewall) als auch iptables ein, um das System vor unbefugtem Zugriff zu schützen:
- ### 1. **`configure_ufw`**
  - Aktiviert UFW mit Standardrichtlinien.
  - Erlaubt spezifische Ports und setzt Logging-Optionen.
  - Standardmäßig werden eingehende Verbindungen blockiert und ausgehende Verbindungen erlaubt.
  - Es werden spezifische Ports freigegeben, z. B. für SSH, Tor und HTTPS.
  - Konfiguration und Status werden geloggt.
- ### 2. **`configure_iptables`**
  - Löscht bestehende Regeln und setzt neue Standards.
  - Schützt SSH-Zugänge durch Ratenbegrenzung.
  - Speichert Regeln in einer Datei zur Persistenz.
  - Löscht bestehende Regeln und setzt sichere Standardrichtlinien.
  - Erlaubt Loopback-Traffic und begrenzt neue SSH-Verbindungen.
  - Speichert Regeln in `/etc/iptables/rules.v4` für den Neustart des Systems.

### **1. UFW (Uncomplicated Firewall)**
**UFW** ist eine benutzerfreundliche Firewall, die auf iptables basiert. Sie ist besonders geeignet für Benutzer, die wenig Erfahrung mit komplexen Firewall-Regeln haben. Das Skript konfiguriert UFW wie folgt:

- **Standardrichtlinien**:
  - **Eingehende Verbindungen**: Alle eingehenden Verbindungen werden standardmäßig blockiert.
  - **Ausgehende Verbindungen**: Alle ausgehenden Verbindungen werden standardmäßig erlaubt.
  - Diese Einstellungen sorgen dafür, dass das System sicher ist und nur Daten versendet, die für den Betrieb notwendig sind.

- **Freigabe spezifischer Ports**:
  - Bestimmte Ports werden explizit für bekannte und notwendige Dienste freigegeben:
    - **Port 22**: Für SSH (Remote-Zugriff auf den Server).
    - **Ports 9050 und 9001**: Für Tor (anonymer Netzwerkverkehr).
    - **Port 443**: Für HTTPS (sichere Webverbindungen).

- **Protokollierung**:
  - Das Skript aktiviert umfassendes Logging für UFW, um sicherzustellen, dass alle Firewall-Aktivitäten dokumentiert werden.
  - Der Status und die Konfiguration werden regelmäßig überprüft und in einer Logdatei festgehalten.

- **Weitere Schutzmaßnahmen**:
  - SSH-Zugriffe werden mit einer Limitierungsregel geschützt, um Brute-Force-Angriffe (wiederholte Versuche, Zugang zu erhalten) zu verhindern:
    - Wenn zu viele Anfragen von derselben IP-Adresse kommen, wird diese blockiert.

---

### **2. iptables**
**iptables** ist ein leistungsstarkes und flexibles Werkzeug, das direkt mit dem Linux-Kernel integriert ist. Es wird verwendet, um detaillierte Regeln für den Netzwerkverkehr zu erstellen. Das Skript verwendet iptables für eine tiefere Kontrolle über die Firewall-Regeln:

- **Löschen bestehender Regeln**:
  - Das Skript entfernt alle vorherigen Regeln, um sicherzustellen, dass keine unerwünschten Konfigurationen übernommen werden:
    - Beispiel: `iptables -F` löscht alle Regeln in der INPUT-, OUTPUT- und FORWARD-Kette.

- **Setzen von Standardrichtlinien**:
  - Eingehender Datenverkehr (**INPUT**): Standardmäßig blockiert.
  - Weitergeleiteter Datenverkehr (**FORWARD**): Standardmäßig blockiert.
  - Ausgehender Datenverkehr (**OUTPUT**): Standardmäßig erlaubt.
  - Diese Richtlinien sorgen dafür, dass nur ausdrücklich erlaubte Verbindungen akzeptiert werden.

- **Erlauben von Loopback-Traffic**:
  - Der Loopback-Traffic (Verbindungen innerhalb des Systems) wird zugelassen, damit interne Dienste wie `localhost` (127.0.0.1) funktionieren.

- **Begrenzung neuer SSH-Verbindungen**:
  - Das Skript setzt eine Regel, um neue SSH-Verbindungen von derselben IP-Adresse innerhalb kurzer Zeit zu begrenzen:
    - Beispiel: Maximal 5 Verbindungsversuche in 60 Sekunden.
    - Dies schützt vor Brute-Force-Angriffen.

- **Speicherung der Regeln**:
  - Die Firewall-Regeln werden in der Datei `/etc/iptables/rules.v4` gespeichert. Diese Datei stellt sicher, dass die Konfiguration beim Neustart des Systems automatisch wiederhergestellt wird.
  - Die Datei wird durch den Befehl `iptables-save` erstellt und kann mit `iptables-restore` geladen werden.

- **Erweiterte Sicherheitsmaßnahmen**:
  - Das Skript blockiert "ungültige Pakete", die häufig von Angreifern genutzt werden, um Sicherheitslücken auszunutzen.
  - ICMP-Pakete (z. B. Ping-Anfragen) können ebenfalls blockiert werden, um das System vor Netzwerkscans zu schützen.

### **Zusammenfassung**
Die Kombination aus UFW und iptables ermöglicht es, sowohl einfache als auch detaillierte Firewall-Konfigurationen zu erstellen. Während UFW eine benutzerfreundliche Oberfläche bietet, sorgt iptables für die tiefere Kontrolle. Das Skript stellt sicher, dass beide Systeme effektiv zusammenarbeiten, um maximale Sicherheit zu gewährleisten.

Falls Sie keine Erfahrung mit Firewalls haben, ist es empfehlenswert, die Standardkonfiguration des Skripts zu belassen. Diese Einstellungen sind optimiert, um gängige Sicherheitsanforderungen zu erfüllen und das System vor Angriffen zu schützen.



------------------------------------------------------------------


# 2. - **Proxy-Management-Beschreibung**
###

Das Skript automatisiert die Verwaltung von Proxy-Listen und deren Integration in ProxyChains. ProxyChains ist ein Werkzeug, das es ermöglicht, den Datenverkehr von Anwendungen über eine oder mehrere Proxy-Server zu leiten. Dies erhöht die Privatsphäre und ermöglicht den Zugriff auf Ressourcen, die normalerweise blockiert sind.

Das Skript automatisiert den Umgang mit Proxy-Listen:
- **ProxyChains**: **`configure_proxychains`**
  - Validiert Proxy-Listen und erstellt eine Konfigurationsdatei für ProxyChains.
  - Unterstützt die Integration mit Tor.
  - Validiert und verarbeitet Proxy-Listen.
  - Konfiguriert ProxyChains mit strikter Kettennutzung und DNS-Leckschutz.
  - Automatisiert das Aktualisieren von Proxys über Systemd-Dienste und Timer.

### **1. Proxy-Verwaltung**
Das Skript übernimmt folgende Aufgaben im Umgang mit Proxys:

- **Abrufen von Proxy-Listen**:
  - Das Skript lädt Proxy-Listen automatisch von einer definierten Quelle herunter. Die URL der Proxy-Liste ist in den Einstellungen vorkonfiguriert und kann angepasst werden.
  - Es wird sichergestellt, dass nur Proxy-Server im Format `IP:Port` akzeptiert werden.

- **Validierung und Verarbeitung**:
  - Nach dem Abrufen der Proxy-Liste wird jede Zeile der Liste auf Gültigkeit überprüft.
  - Gültige Proxys werden in einer separaten Datei (`validated_proxies.txt`) gespeichert, um sie in ProxyChains zu verwenden.
  - Doppelte Einträge werden entfernt, um die Liste sauber und effizient zu halten.

---

### **2. ProxyChains-Integration**
**ProxyChains** ist ein leistungsstarkes Tool, das den Datenverkehr durch eine Kette von Proxys leitet. Das Skript konfiguriert ProxyChains folgendermaßen:

- **Strikte Kettennutzung**:
  - ProxyChains wird so eingerichtet, dass der Datenverkehr strikt durch die Reihenfolge der definierten Proxys geleitet wird.
  - Dadurch wird sichergestellt, dass alle definierten Proxys in der Kette verwendet werden, bevor der Datenverkehr das Ziel erreicht.

- **DNS-Leckschutz**:
  - DNS-Anfragen (Domain Name System) werden ebenfalls durch die Proxys geleitet. Dies verhindert, dass DNS-Anfragen direkt vom System gesendet werden, was ein potenzielles Sicherheitsrisiko darstellen könnte.
  - Diese Funktion wird durch die Aktivierung von `proxy_dns` in der ProxyChains-Konfiguration gewährleistet.

- **Integration mit Tor**:
  - Standardmäßig wird der Tor-SOCKS5-Proxy (`127.0.0.1:9050`) als letzter Eintrag in der Proxy-Kette hinzugefügt. Dies ergänzt die Anonymisierungsfunktionen von ProxyChains.

---

### **3. Automatisierung mit Systemd**
Das Skript richtet systemd-Dienste und Timer ein, um die Proxy-Listen regelmäßig zu aktualisieren. Dies geschieht wie folgt:

- **Systemd-Dienst für Proxy-Updates**:
  - Der Dienst (`update_proxies.service`) wird beim Systemstart ausgeführt und sorgt dafür, dass die Proxy-Liste aktualisiert wird.
  - Der Dienst ruft das Skript `update_proxies.sh` auf, das für das Abrufen, Validieren und Speichern der Proxys verantwortlich ist.

- **Systemd-Timer für regelmäßige Updates**:
  - Ein systemd-Timer (`update_proxies.timer`) wird eingerichtet, um das Aktualisierungsskript alle 30 Minuten auszuführen.
  - Dies stellt sicher, dass die Proxy-Liste immer aktuell bleibt, ohne dass manuelle Eingriffe erforderlich sind.

---

### **4. Technische Details**
- **Proxy-Quell-URL**:
  - Die URL der Proxy-Liste ist vorkonfiguriert und kann in der Umgebungsvariablen `PROXY_API_URL1` angepasst werden.
  - Standard-URL: `https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt`

- **Konfigurationsdateien**:
  - **ProxyChains-Konfigurationsdatei**:
    - Pfad: `/etc/proxychains.conf`
    - Enthält die Einstellung für strikte Kettennutzung, DNS-Leckschutz und die Liste der Proxys.
  - **Validierte Proxy-Liste**:
    - Pfad: `/etc/proxychains/validated_proxies.txt`
    - Wird automatisch vom Skript aktualisiert.

- **Logdateien**:
  - Alle Aktivitäten im Zusammenhang mit Proxy-Updates werden in `/var/log/update_proxies.log` protokolliert. Dies umfasst:
    - Erfolgreiche Aktualisierungen.
    - Fehler beim Abrufen der Proxy-Liste.
    - Details zur Anzahl der gefundenen und validierten Proxys.


### **Zusammenfassung**
Das Proxy-Management-Modul im Skript stellt sicher, dass ProxyChains effektiv und sicher konfiguriert ist. Durch die Automatisierung von Proxy-Updates und die Integration mit Tor wird sowohl die Privatsphäre als auch der Zugriff auf eingeschränkte Inhalte optimiert. Dank der systemd-Dienste und Timer funktioniert dies völlig autonom, ohne dass Benutzer manuell eingreifen müssen.


------------------------------------------------------------------


# 3. - **Überwachung und Protokollierung**
###

Das Skript richtet mehrere Werkzeuge zur Überwachung und Protokollierung ein, um die Sicherheit des Systems zu erhöhen und dem Administrator nützliche Einblicke in die Aktivitäten des Systems zu geben. Diese Werkzeuge arbeiten zusammen, um potenzielle Sicherheitsbedrohungen zu erkennen, darauf zu reagieren und detaillierte Berichte zu erstellen.

Verschiedene Überwachungstools werden installiert und konfiguriert:
- **Fail2Ban**: **`configure_fail2ban`**
  - Überwacht Logs und sperrt IPs bei verdächtigem Verhalten.
  - Konfiguriert Standard- und benutzerdefinierte Jails.
  - Überwacht Logdateien und blockiert IPs bei Brute-Force-Angriffen.
  - Konfiguriert mehrere Jails für SSH, Apache und Nginx.
- **Logwatch**:
  - Sendet tägliche Berichte per E-Mail.
- **Rsyslog**:
  - Fügt benutzerdefinierte Protokollierungsregeln hinzu.

---

### **1. Fail2Ban**
**Fail2Ban** ist ein beliebtes Überwachungstool, das Logdateien auf verdächtige Aktivitäten überwacht. Es blockiert IP-Adressen, die sich durch wiederholte Fehlversuche oder verdächtiges Verhalten auszeichnen. Das Skript konfiguriert Fail2Ban folgendermaßen:

- **Überwachung von Logdateien**:
  - Fail2Ban durchsucht Logdateien wie `/var/log/auth.log` oder `/var/log/nginx/error.log`, um verdächtige Aktivitäten zu erkennen.
  - Es erkennt Brute-Force-Angriffe (wiederholte Login-Versuche) und sperrt die entsprechenden IP-Adressen automatisch.

- **Jails (Regeln für spezifische Dienste)**:
  - Jails sind vorkonfigurierte Regeln, die die Erkennung und Blockierung verdächtiger Aktivitäten für bestimmte Dienste definieren. Das Skript richtet mehrere Jails ein:
    - **SSH**:
      - Blockiert IPs nach einer festgelegten Anzahl fehlgeschlagener Login-Versuche.
      - Sperrdauer beträgt standardmäßig 24 Stunden.
    - **Apache/Nginx**:
      - Überwacht fehlgeschlagene Authentifizierungsversuche und blockiert diese IPs.
      - Dient zum Schutz von Webservern vor unbefugtem Zugriff.
    - **Recidive**:
      - IPs, die mehrfach gebannt wurden, erhalten eine längere Sperrzeit (z. B. 1 Woche).

- **Konfigurationsdateien**:
  - **Hauptkonfiguration**:
    - Pfad: `/etc/fail2ban/jail.local`
    - Enthält die Einstellungen für Jails, Sperrzeiten und maximale Fehlversuche.
  - **Filter**:
    - Fail2Ban verwendet Filter (z. B. `sshd-ddos.conf`), um verdächtige Muster in Logdateien zu erkennen.
    - Diese Filter sind anpassbar und werden im Verzeichnis `/etc/fail2ban/filter.d/` gespeichert.

- **Dienstverwaltung**:
  - Das Skript aktiviert und startet den Fail2Ban-Dienst, sodass er automatisch beim Systemstart läuft.

---

### **2. Logwatch**
**Logwatch** ist ein Tool, das tägliche Berichte über Systemaktivitäten generiert und per E-Mail an den Administrator sendet. Das Skript richtet Logwatch ein, um eine detaillierte Übersicht der Systemprotokolle zu liefern:

- **Berichtserstellung**:
  - Logwatch durchsucht Systemlogdateien und fasst die wichtigsten Ereignisse zusammen.
  - Es erstellt Berichte über Sicherheitsvorfälle, Systemstatus und andere relevante Aktivitäten.

- **E-Mail-Berichte**:
  - Der Administrator erhält täglich einen Bericht per E-Mail.
  - Der Bericht enthält Informationen wie:
    - Fehlgeschlagene Login-Versuche.
    - Änderungen an Systemdiensten.
    - Netzwerkaktivitäten.

- **Automatisierung**:
  - Das Skript erstellt einen Cronjob (`/etc/cron.daily/00logwatch`), der Logwatch täglich ausführt.
  - Der Cronjob sorgt dafür, dass die Berichte regelmäßig erstellt und versendet werden.

---

### **3. Rsyslog**
**Rsyslog** ist ein leistungsstarkes Protokollierungstool, das Systemlogdateien verarbeitet und speichert. Es ermöglicht die zentrale Verwaltung und Strukturierung von Logdaten. Das Skript erweitert die Rsyslog-Konfiguration folgendermaßen:

- **Benutzerdefinierte Protokollierungsregeln**:
  - Es werden zusätzliche Regeln zur Strukturierung der Logdateien hinzugefügt:
    - **Allgemeine Systemnachrichten**: Werden in `/var/log/messages` gespeichert.
    - **Sicherheitsrelevante Nachrichten**: Werden in `/var/log/secure` protokolliert.
    - **E-Mails**: Werden in `/var/log/maillog` protokolliert.
    - **Cronjobs**: Werden in `/var/log/cron` gespeichert.

- **Sicherung der Konfiguration**:
  - Bevor Änderungen an der Rsyslog-Konfiguration vorgenommen werden, erstellt das Skript ein Backup der Originaldatei (`/etc/rsyslog.conf.backup`).

- **Dienstverwaltung**:
  - Nach der Konfigurationsänderung wird der Rsyslog-Dienst neu gestartet, um die Änderungen zu übernehmen.

- **Erweiterbarkeit**:
  - Rsyslog kann so angepasst werden, dass es Logdaten an entfernte Server sendet oder spezielle Filterregeln verwendet, um nur bestimmte Ereignisse zu protokollieren.

---

### **Zusammenarbeit der Tools**
Die drei Werkzeuge (Fail2Ban, Logwatch und Rsyslog) arbeiten zusammen, um ein umfassendes Überwachungssystem zu bieten:
1. **Fail2Ban** schützt aktiv vor Angriffen, indem es IPs blockiert.
2. **Logwatch** liefert tägliche Berichte, die Administratoren über den Status und Vorfälle informieren.
3. **Rsyslog** strukturiert und speichert Logdaten, die von den anderen Tools genutzt werden können.

### **Zusammenfassung**
Die Überwachungs- und Protokollierungsfunktionen des Skripts stellen sicher, dass das System vor unerwünschten Zugriffen geschützt ist und Administratoren stets über relevante Ereignisse informiert werden. Alle Konfigurationen sind standardmäßig optimiert, können jedoch leicht angepasst werden, um spezifische Anforderungen zu erfüllen.


------------------------------------------------------------------


# 4. - **Netzwerk und DNS**
###

Das Netzwerk- und DNS-Modul des Skripts stellt sicher, dass das System zuverlässig arbeitet und gleichzeitig mögliche Sicherheitsrisiken minimiert werden. Es beinhaltet Funktionen zur Erkennung des primären Netzwerkinterfaces, zur Konfiguration sicherer DNS-Server und zur Durchführung eines Netzwerkscans.

Das Skript erkennt das primäre Netzwerkinterface und konfiguriert DNS-Einstellungen:
- **DNS-Leckschutz**:
  - Konfiguriert `resolv.conf`, um zuverlässige DNS-Server zu verwenden (z. B. 1.1.1.1 und 8.8.8.8).
  - Verhindert, dass DHCP den DNS überschreibt.
- **Netzwerkscan**:
  - Führt einen Scan des lokalen Netzwerks durch, um aktive Geräte zu identifizieren.

---

### **1. Erkennung des primären Netzwerkinterfaces**
Das Skript erkennt automatisch die Hauptnetzwerkschnittstelle des Systems (z. B. `eth0` oder `wlan0`). Dies ist notwendig, um die Netzwerkkommunikation ordnungsgemäß zu konfigurieren und zu überwachen.

- **Wie das primäre Interface erkannt wird**:
  - Das Skript verwendet den Befehl `ip route`, um die Standardroute des Systems zu identifizieren. Die Standardroute zeigt, welche Netzwerkschnittstelle (Interface) für den ausgehenden Datenverkehr verwendet wird.
  - Beispiel: `ip route | grep default | awk '{print $5}'` gibt die primäre Schnittstelle zurück.

- **Fallback-Mechanismus**:
  - Falls keine Standardroute gefunden wird, versucht das Skript, bekannte Interfaces wie `eth0` (verkabeltes Netzwerk) oder `wlan0` (WLAN) als primäre Schnittstelle festzulegen.
  - Wenn keine Schnittstelle erkannt wird, protokolliert das Skript einen Fehler und fordert die Überprüfung der Netzwerkeinstellungen.

- **Protokollierung**:
  - Die erkannte Schnittstelle wird in die Logdatei geschrieben, um sicherzustellen, dass Änderungen nachvollziehbar sind.

---

### **2. DNS-Leckschutz**
Der DNS-Leckschutz stellt sicher, dass DNS-Anfragen (zur Namensauflösung von Domains) nicht an unsichere oder ungewollte Server gesendet werden. Dies schützt die Privatsphäre des Systems und verhindert potenzielle Sicherheitsrisiken.

- **Konfiguration von `resolv.conf`**: 
  - Das Skript überschreibt die Datei `/etc/resolv.conf`, um zuverlässige DNS-Server zu verwenden:
    - **Cloudflare DNS**: `1.1.1.1` und `1.0.0.1`
    - **Google DNS**: `8.8.8.8` und `8.8.4.4`
  - Diese DNS-Server sind bekannt für ihre Zuverlässigkeit, Geschwindigkeit und Datenschutzrichtlinien.

- **Validierung der DNS-Server**:
  - Nachdem die DNS-Server konfiguriert wurden, überprüft das Skript, ob sie erreichbar sind. Dies geschieht durch Testabfragen mit dem Tool `dig`.
  - Beispiel: `dig @1.1.1.1 google.com` prüft, ob der DNS-Server `1.1.1.1` korrekt auf die Domain `google.com` antwortet.
  - Falls ein DNS-Server nicht erreichbar ist, wird dies im Log vermerkt, und das Skript setzt die Konfiguration fort.

- **Verhindern von DHCP-Überschreibungen**:
  - Um zu verhindern, dass der DHCP-Client (der automatisch Netzwerkeinstellungen bezieht) die Konfiguration von `/etc/resolv.conf` ändert, wird die Datei mit einem **immutable-Flag** geschützt:
    - `chattr +i /etc/resolv.conf` macht die Datei unveränderbar.
  - Dies stellt sicher, dass nur das Skript (oder der Root-Benutzer) Änderungen an der DNS-Konfiguration vornehmen kann.

---

### **3. Netzwerkscan**
Der Netzwerkscan ist eine Funktion, die das lokale Netzwerk auf aktive Geräte überprüft. Dies hilft, mögliche Sicherheitsprobleme zu erkennen, wie z. B. unbekannte oder nicht autorisierte Geräte.

- **Erkennung der lokalen IP-Range**:
  - Das Skript verwendet die IP-Adresse des Systems, um den Bereich des lokalen Netzwerks zu bestimmen:
    - Beispiel: Wenn die lokale IP-Adresse `192.168.1.10` ist, wird der Bereich `192.168.1.0/24` gescannt.
  - Dies wird mit dem Befehl `hostname -I` und `cut` ermittelt.

- **Durchführung des Scans**:
  - Der Scan wird mit dem Tool `nmap` durchgeführt, das eine detaillierte Übersicht über aktive Geräte im Netzwerk bietet.
  - Standardmäßig wird ein TCP-SYN-Scan verwendet, um Geräte zu erkennen, die auf bestimmte Ports reagieren.

- **Ergebnisse speichern**:
  - Die Ergebnisse des Netzwerkscans werden in `/var/log/nmap_scan.log` gespeichert, sodass sie später überprüft werden können.
  - Protokollierte Informationen umfassen die IP-Adressen und offenen Ports der erkannten Geräte.

---

### **Zusammenarbeit der Funktionen**
1. **Primäres Interface**: Stellt sicher, dass alle netzwerkbezogenen Operationen auf der richtigen Schnittstelle ausgeführt werden.
2. **DNS-Leckschutz**: Garantiert, dass alle DNS-Anfragen sicher und zuverlässig verarbeitet werden.
3. **Netzwerkscan**: Bietet einen Überblick über das lokale Netzwerk und hilft, unbefugten Zugriff zu erkennen.

### **Zusammenfassung**
Das Netzwerk- und DNS-Modul bietet eine nahtlose Integration von Sicherheits- und Diagnosefunktionen. Durch die Kombination aus DNS-Leckschutz und Netzwerkscans wird die Sicherheit der Netzwerkverbindungen erhöht und gleichzeitig ein Überblick über das lokale Netzwerk gewährleistet. Diese Funktionen arbeiten automatisch, sodass keine manuellen Eingriffe erforderlich sind.


------------------------------------------------------------------


# 5. - **Webserver-Sicherheit**
###

Das Skript richtet einen sicheren und datenschutzfreundlichen Webserver mit **Nginx** ein. Dabei werden Sicherheitsmaßnahmen wie die Konfiguration von HTTPS, die Erstellung von SSL-Zertifikaten und die Integration eines **SOCKS5-Proxys** (über Tor) umgesetzt. Ziel ist es, eine verschlüsselte Verbindung bereitzustellen und gleichzeitig die Privatsphäre der Benutzer zu schützen.

**`configure_openssl`**
- Generiert selbstsignierte Zertifikate für HTTPS.
- Erstellt sichere Diffie-Hellman-Parameter (DH).

**`configure_nginx_ssl`**
- Konfiguriert Nginx mit HTTPS-Unterstützung.
- Aktiviert SOCKS5-Proxy-Leitung über Nginx.

Das Skript richtet einen sicheren Nginx-Webserver ein:
- **SSL-Konfiguration**:
  - Generiert selbstsignierte SSL-Zertifikate und DH-Parameter.
  - Erzwingt HTTPS und leitet HTTP-Anfragen weiter.
- **SOCKS5-Proxy-Unterstützung**:
  - Nginx leitet Anfragen über den Tor-SOCKS5-Proxy.

---

### **1. SSL-Konfiguration**
Die **Transport Layer Security (TLS)** ist entscheidend für sichere Verbindungen im Internet. Das Skript stellt sicher, dass alle HTTP-Anfragen auf HTTPS umgeleitet werden und alle Verbindungen verschlüsselt sind.

- **Selbstsignierte SSL-Zertifikate**:
  - Das Skript erstellt automatisch ein selbstsigniertes SSL-Zertifikat mithilfe von **OpenSSL**, falls kein Zertifikat vorhanden ist.
  - Das Zertifikat wird in den Verzeichnissen `/etc/ssl/private/` (für den Schlüssel) und `/etc/ssl/certs/` (für das Zertifikat) gespeichert.
  - Beispiel: 
    - Private Schlüsseldatei: `/etc/ssl/private/nginx-selfsigned.key`
    - Zertifikatsdatei: `/etc/ssl/certs/nginx-selfsigned.crt`

- **Diffie-Hellman-Parameter (DH)**:
  - DH-Parameter werden verwendet, um zusätzliche Sicherheit bei der Schlüsselaushandlung zu gewährleisten.
  - Falls keine DH-Parameter vorhanden sind, generiert das Skript diese automatisch und speichert sie in `/etc/ssl/certs/dhparam.pem`.
  - Dieser Vorgang kann je nach Systemleistung einige Minuten dauern.

- **HTTPS-Erzwingung**:
  - Alle HTTP-Anfragen (Port 80) werden automatisch auf HTTPS (Port 443) umgeleitet.
  - Dies stellt sicher, dass alle Verbindungen verschlüsselt sind und keine Daten im Klartext übertragen werden.

- **SSL-Snippet für Nginx**:
  - Das Skript erstellt eine Konfigurationsdatei (`/etc/nginx/snippets/self-signed.conf`), die die SSL-Parameter definiert:
    - Unterstützte Protokolle: TLSv1.2 und TLSv1.3.
    - Sichere Chiffren: Nur moderne und sichere Verschlüsselungsalgorithmen werden verwendet.
    - Zusätzliche Sicherheitsheader:
      - `Strict-Transport-Security`: Erzwingt die Verwendung von HTTPS für Subdomains.
      - `X-Content-Type-Options`: Verhindert MIME-Typ-Sniffing.
      - `X-Frame-Options`: Schutz vor Clickjacking.
      - `X-XSS-Protection`: Schutz vor Cross-Site-Scripting (XSS).

---

### **2. SOCKS5-Proxy-Unterstützung**
Das Skript integriert **Tor** als SOCKS5-Proxy in den Nginx-Webserver, um den Datenverkehr anonym zu leiten. Dies ist besonders nützlich für Benutzer, die ihre Identität und ihren Standort schützen möchten.

- **Tor-SOCKS5-Proxy**:
  - Der Tor-Dienst wird auf dem lokalen System ausgeführt und bietet einen SOCKS5-Proxy unter `127.0.0.1:9050`.
  - Nginx leitet Anfragen über diesen Proxy weiter, wodurch die eigentliche IP-Adresse des Servers verborgen bleibt.

- **Nginx-Konfiguration**:
  - Das Skript erstellt eine neue Site-Konfigurationsdatei (`/etc/nginx/sites-available/tor_proxy`), die wie folgt funktioniert:
    - **HTTP (Port 80)**:
      - Alle Anfragen werden auf HTTPS (Port 443) umgeleitet.
    - **HTTPS (Port 443)**:
      - Anfragen werden verschlüsselt und über den Tor-SOCKS5-Proxy weitergeleitet.
      - Die Verbindung zwischen dem Client und Nginx ist verschlüsselt, während die Verbindung zwischen Nginx und Tor anonymisiert ist.

- **Proxy-Einstellungen in Nginx**:
  - Das Skript fügt die notwendigen Einstellungen hinzu, um sicherzustellen, dass die Client-Informationen korrekt weitergeleitet werden:
    - `proxy_pass`: Leitet Anfragen an den Tor-Proxydienst weiter.
    - `proxy_set_header`: Stellt sicher, dass die Header-Einstellungen wie `Host` und `X-Real-IP` korrekt sind.

---

### **3. Automatisierung und Verwaltung**
- **Automatische Aktivierung**:
  - Die Nginx-Konfiguration wird automatisch aktiviert, indem ein symbolischer Link von `/etc/nginx/sites-available/tor_proxy` nach `/etc/nginx/sites-enabled/tor_proxy` erstellt wird.

- **Konfigurationstest und Neustart**:
  - Nach jeder Änderung testet das Skript die Nginx-Konfiguration mit `nginx -t`, um sicherzustellen, dass keine Syntaxfehler vorliegen.
  - Bei erfolgreichem Test wird der Nginx-Dienst neu geladen, um die neue Konfiguration zu übernehmen.

- **Fehlerbehandlung**:
  - Falls die Generierung von SSL-Zertifikaten oder die Konfiguration fehlschlägt, werden detaillierte Fehlermeldungen in die Logdatei geschrieben.

### **Zusammenarbeit der Funktionen**
1. **SSL-Konfiguration**:
   - Schützt alle Verbindungen zwischen dem Client und dem Server durch Verschlüsselung.
2. **Tor-Proxy**:
   - Anonymisiert den ausgehenden Datenverkehr und schützt die Privatsphäre des Servers.
3. **HTTPS-Erzwingung**:
   - Stellt sicher, dass keine sensiblen Daten unverschlüsselt übertragen werden.

---

### **Zusammenfassung**
Das Modul zur Webserver-Sicherheit sorgt für eine robuste und sichere Verbindung zwischen Client und Server. Durch die Kombination aus HTTPS und dem Tor-SOCKS5-Proxy wird nicht nur die Integrität der Daten, sondern auch die Anonymität des Servers gewährleistet. Das Skript automatisiert alle wichtigen Schritte, sodass Benutzer keine manuelle Konfiguration vornehmen müssen.


------------------------------------------------------------------


# 6. - **Systemd-Dienste**
###

Systemd-Dienste sind ein integraler Bestandteil moderner Linux-Distributionen und ermöglichen die Automatisierung und Verwaltung von Systemprozessen. Das Skript erstellt und konfiguriert mehrere systemd-Dienste und Timer, um wichtige Aufgaben zu automatisieren. Dadurch wird sichergestellt, dass Sicherheits- und Netzwerkeinstellungen beim Booten oder in regelmäßigen Intervallen angewendet werden.

Das Skript erstellt und aktiviert verschiedene Dienste:
- **UFW-Dienst**:
  - Startet und verwaltet die UFW-Firewall beim Systemstart.
- **iptables-Dienst**:
  - Stellt iptables-Regeln beim Booten wieder her.
- **Proxy-Update-Dienst**:
  - Aktualisiert die Proxy-Liste beim Start.
- **Proxy-Update-Timer**:
  - Führt das Proxy-Update-Skript alle 30 Minuten aus.

---

### **1. UFW-Dienst**
Der **UFW-Dienst** wird eingerichtet, um die Uncomplicated Firewall (UFW) automatisch beim Systemstart zu aktivieren und zu verwalten.
- **Aufgaben des UFW-Dienstes**:
  - UFW wird gestartet und aktiviert, sodass die Firewall-Regeln beim Booten des Systems angewendet werden.
  - UFW wird im Hintergrund überwacht, um sicherzustellen, dass es aktiv bleibt.

- **Technische Umsetzung**:
  - Das Skript erstellt eine systemd-Service-Datei namens `/etc/systemd/system/ufw.service`.
  - Die Service-Datei enthält folgende Konfiguration:
    - **ExecStart**: Führt das Skript `/usr/local/bin/ufw.sh` aus, das UFW aktiviert und dauerhaft laufen lässt.
    - **Restart**: Falls der Dienst fehlschlägt, wird er automatisch neu gestartet.
    - **Type**: `simple`, damit der Dienst im Vordergrund läuft.

- **Automatisierung**:
  - Der Dienst wird mit `systemctl enable ufw.service` so konfiguriert, dass er beim Booten gestartet wird.
  - Mit `systemctl start ufw.service` wird der Dienst unmittelbar aktiviert.

---

### **2. iptables-Dienst**
Der **iptables-Dienst** stellt sicher, dass alle iptables-Regeln beim Booten des Systems wiederhergestellt werden. Dies ist notwendig, da iptables-Regeln standardmäßig nicht persistent sind.
- **Aufgaben des iptables-Dienstes**:
  - Lädt die gespeicherten iptables-Regeln aus der Datei `/etc/iptables/rules.v4`.
  - Wendet diese Regeln direkt nach dem Booten an, um die Netzwerksicherheit sicherzustellen.

- **Technische Umsetzung**:
  - Das Skript erstellt eine systemd-Service-Datei namens `/etc/systemd/system/iptables.service`.
  - Die Service-Datei enthält folgende Konfiguration:
    - **ExecStart**: Führt das Skript `/usr/local/bin/iptables.sh` aus, das die gespeicherten Regeln mit `iptables-restore` lädt.
    - **Type**: `oneshot`, da die Wiederherstellung der Regeln nur einmal beim Start erfolgen muss.
    - **RemainAfterExit**: `yes`, damit der Status des Dienstes nach der Ausführung als aktiv angezeigt wird.

- **Automatisierung**:
  - Der Dienst wird mit `systemctl enable iptables.service` für den automatischen Start konfiguriert.
  - Mit 

---

### **3. Proxy-Update-Dienst**
Der **Proxy-Update-Dienst** ist für die Aktualisierung der Proxy-Liste beim Systemstart verantwortlich. Er sorgt dafür, dass ProxyChains immer mit einer aktuellen Liste von Proxys arbeitet.
- **Aufgaben des Proxy-Update-Dienstes**:
  - Lädt neue Proxy-Listen von definierten Quellen herunter.
  - Validiert die Proxy-Listen und speichert sie in der Datei `/etc/proxychains/validated_proxies.txt`.

- **Technische Umsetzung**:
  - Das Skript erstellt eine systemd-Service-Datei namens `/etc/systemd/system/update_proxies.service`.
  - Die Service-Datei enthält folgende Konfiguration:
    - **ExecStart**: Führt das Skript `/usr/local/bin/update_proxies.sh` aus.
    - **Type**: `oneshot`, da die Aktualisierung der Proxy-Liste nur einmal beim Start erfolgen muss.
    - **RemainAfterExit**: `true`, um den Status des Dienstes beizubehalten.

- **Automatisierung**:
  - Der Dienst wird mit `systemctl enable update_proxies.service` für den Start beim Booten eingerichtet.
  - Mit `systemctl start update_proxies.service` wird der Dienst sofort ausgeführt.

---

### **4. Proxy-Update-Timer**
Der **Proxy-Update-Timer** ergänzt den Proxy-Update-Dienst, indem er das Proxy-Aktualisierungsskript in regelmäßigen Intervallen ausführt. Dadurch bleibt die Proxy-Liste immer aktuell.
- **Aufgaben des Proxy-Update-Timers**:
  - Führt das Proxy-Aktualisierungsskript (`update_proxies.sh`) alle 30 Minuten aus.
  - Stellt sicher, dass ProxyChains mit aktuellen und funktionierenden Proxys arbeitet.

- **Technische Umsetzung**:
  - Das Skript erstellt eine systemd-Timer-Datei namens `/etc/systemd/system/update_proxies.timer`.
  - Die Timer-Datei enthält folgende Konfiguration:
    - **OnCalendar**: `*:0/30`, was bedeutet, dass der Timer alle 30 Minuten ausgeführt wird.
    - **Persistent**: `true`, sodass verpasste Timer-Ereignisse nachgeholt werden, falls das System ausgeschaltet war.

- **Automatisierung**:
  - Der Timer wird mit `systemctl enable update_proxies.timer` aktiviert und startet automatisch mit dem System.
  - Mit `systemctl start update_proxies.timer` wird der Timer sofort gestartet.

---

### **Zusammenarbeit der Dienste**
Die systemd-Dienste arbeiten zusammen, um eine sichere und zuverlässige Systemumgebung zu gewährleisten:
1. **UFW-Dienst**: Aktiviert die Firewall und verhindert unbefugten Zugriff.
2. **iptables-Dienst**: Stellt detaillierte Netzwerksicherheitsregeln wieder her.
3. **Proxy-Update-Dienst**: Sorgt dafür, dass ProxyChains mit aktuellen Proxys arbeitet.
4. **Proxy-Update-Timer**: Hält die Proxy-Liste durch regelmäßige Updates aktuell.

### **Zusammenfassung**
Die systemd-Dienste und Timer sind so konfiguriert, dass sie alle sicherheits- und netzwerkrelevanten Aufgaben automatisieren. Dadurch wird die Notwendigkeit manueller Eingriffe minimiert, und die Sicherheit des Systems bleibt auch nach einem Neustart gewährleistet. Alle Dienste können über systemd-Befehle wie `systemctl status`, `start`, `stop` oder `restart` verwaltet werden.