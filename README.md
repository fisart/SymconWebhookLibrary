# Webhook Library

## 1. Wozu wird dies benötigt? (Das Problem)

Als IP-Symcon Entwickler oder Power-User installieren Sie oft diverse Module, die "Webhooks" registrieren (erreichbare URLs wie `http://ip-symcon/hook/example`).

**Das Problem:**

- Es gibt keine zentrale "Index-Seite" oder ein "Dashboard" im Frontend, um zu sehen, welche Webhooks aktuell aktiv sind.
- Um einen Webhook zu testen oder zu nutzen, müssen Sie sich die URL merken oder diese tief in der IP-Symcon Verwaltungskonsole nachschlagen (Kern-Instanzen -> WebHook Control).
- Das manuelle Navigieren zu diesen URLs ist mühsam.

**Die Lösung:**
Das **Webhook Library** Modul löst dies, indem es automatisch eine dynamische HTML-Landingpage generiert, die **alle** auf Ihrem System registrierten Webhooks auflistet. Es fungiert als klickbares Verzeichnis für Ihren Server.

---

## 2. Funktionalität

- **Automatische Erkennung:** Liest automatisch die Konfiguration der lokalen IP-Symcon WebHook Control Instanz aus.
- **Dynamische Auflistung:** Generiert eine saubere, responsive HTML-Liste aller verfügbaren Webhooks.
- **Ein-Klick-Zugriff:** Ein Klick auf einen Listeneintrag öffnet den entsprechenden Webhook in einem **neuen Browser-Tab** (`target="_blank"`).
- **Sicherheitsintegration:** Nahtlose Integration mit dem "Secrets Manager" (Passkey Modul). Der Zugriff auf die Bibliothek ist nur authentifizierten Benutzern gestattet.

---

## 3. Der Prozess (Wie es funktioniert)

Wenn ein Benutzer die Bibliotheks-URL aufruft (z.B. `/hook/library`), folgt das Modul diesem Logikfluss:

1.  **Eingehende Anfrage:** Das Modul empfängt die HTTP-Anfrage über seinen eigenen registrierten Hook.
2.  **Authentifizierungsprüfung:**
    - Das Modul prüft die konfigurierte `SecretsManagerID`.
    - Es ruft `SEC_IsPortalAuthenticated($instanceID)` auf, um die Sitzung des Benutzers zu verifizieren.
    - **Falls nicht autorisiert:** Der Benutzer wird zum Secrets Manager Login-Portal weitergeleitet.
    - **Falls autorisiert:** Der Prozess wird fortgesetzt.
3.  **Datenabruf:**
    - Das Modul lokalisiert die Core WebHook Control Instanz (GUID `{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}`).
    - Es ruft die rohe `Hooks` Eigenschaft (JSON) ab, welche alle registrierten Pfade und Ziel-IDs enthält.
4.  **HTML-Generierung:**
    - Das Modul konstruiert eine vollständige HTML5-Seite mit eingebettetem CSS für das Styling.
    - Es iteriert durch die Liste der Webhooks und generiert `<a>` Tags für jeden Eintrag.
5.  **Ausgabe:** Das generierte HTML wird an den Browser zurückgesendet und zeigt die Liste an.

---

## 4. Verwendung (Beispiel)

### Voraussetzung

- IP-Symcon 6.0 oder höher.
- Das **Secrets Manager** (Passkey) Modul muss installiert und konfiguriert sein.

Kurzbeschreibung der notwendigen Vorbereitungen im **SecretsManager**, damit die Passkey-Funktionalität (Biometrie) für andere Module und Skripte zur Verfügung steht.

### Voraussetzungen für die Passkey-Nutzung

Damit dieses Modul die biometrische Authentifizierung über den SecretsManager nutzen kann, müssen folgende Vorbereitungen im Tresor getroffen sein:

1.  **Sichere Verbindung (HTTPS):** Passkeys funktionieren technisch nur über eine verschlüsselte Verbindung (z. B. IP-Symcon Connect oder ein gültiges SSL-Zertifikat).
2.  **Registrierungs-Passwort:** Im SecretsManager muss auf der obersten Ebene (**root**) ein Record mit dem exakten Namen `RegistrationPassword` erstellt werden. Dieser muss ein Feld namens `PW` mit einem frei wählbaren Passwort enthalten.
3.  **Geräte-Registrierung:** Jedes Endgerät (Smartphone, Tablet oder PC) muss einmalig verknüpft werden. Rufen Sie dazu die Registrierungs-URL Ihrer SecretsManager-Instanz auf:
    `https://[Ihre-Symcon-URL]/hook/secrets_[ID]?register=1&pass=[Ihr-Passwort]`
4.  **WebHook-Aktivität:** Der WebHook des SecretsManager muss aktiv sein (in Version 3.0 automatisch für alle Modi der Fall).

---

### Einrichtung

1.  Installieren Sie das **Webhook Library** Modul.
2.  Erstellen Sie eine Instanz von **Webhook Library** (z.B. in einer Kategorie namens "System").
3.  Wählen Sie im Konfigurationsformular Ihre **Secrets Manager** Instanz im Dropdown-Menü aus.
4.  Klicken Sie auf **Übernehmen**.

### Nutzung

1.  Öffnen Sie Ihren Webbrowser.
2.  Navigieren Sie zu: `http://<IP-Symcon-IP>:3777/hook/library`
    - _(Oder nutzen Sie Ihre Symcon Connect URL: `https://<xxx>.ipmagic.de/hook/library`)_
3.  **Login:** Sie werden aufgefordert, sich mittels Passkey/Biometrie über den Secrets Manager zu authentifizieren.
4.  **Durchsuchen:** Sobald Sie eingeloggt sind, sehen Sie die Liste aller Webhooks.
5.  **Klick:** Klicken Sie auf einen Link, um diesen spezifischen Webhook in einem neuen Tab zu öffnen.

---

## 5. Technische Details

- **Modul-Präfix:** `WHL`
- **WebHook URL:** `/hook/library`
- **Abhängigkeiten:** Benötigt `Secrets Manager` für die Authentifizierungslogik.

````

### File: `README.md`

```markdown
# Webhook Library

## 1. Why do you need this? (The Problem)

As an IP-Symcon developer or power user, you often install various modules that register "Webhooks" (accessible URLs like `http://ip-symcon/hook/example`).

**The Problem:**

- There is no central "Index Page" or "Dashboard" in the front-end to see which Webhooks are currently active.
- To test or use a Webhook, you must memorize the URL or look it up deep inside the IP-Symcon Management Console (Core Instances -> WebHook Control).
- Navigating to these URLs manually is tedious.

**The Solution:**
The **Webhook Library** module solves this by automatically generating a dynamic HTML landing page that lists **all** registered Webhooks on your system. It acts as a clickable directory for your server.

---

## 2. Functionality

- **Auto-Discovery:** Automatically reads the configuration of the local IP-Symcon WebHook Control instance.
- **Dynamic Listing:** Generates a clean, responsive HTML list of all available hooks.
- **One-Click Access:** Clicking a list item opens the respective Webhook in a **new browser tab** (`target="_blank"`).
- **Security Integration:** Seamlessly integrates with the "Secrets Manager" (Passkey Module). Access to the library is restricted to authenticated users only.

### Prerequisites for Passkey Usage

To allow this module to utilize biometric authentication via the SecretsManager, the following preparations must be completed within the vault:

1.  **Secure Connection (HTTPS):** Passkeys strictly require an encrypted connection (e.g., IP-Symcon Connect or a valid SSL certificate) to function.
2.  **Registration Password:** A record named exactly `RegistrationPassword` must be created at the vault's **root** level. This record must contain a field named `PW` with a password of your choice.
3.  **Device Enrollment:** Each end device (smartphone, tablet, or PC) must be linked once. To do this, navigate to the registration URL of your SecretsManager instance:
    `https://[Your-Symcon-URL]/hook/secrets_[ID]?register=1&pass=[Your-Password]`
4.  **WebHook Status:** The SecretsManager WebHook must be active (enabled automatically for all modes in version 3.0+).

---

## 3. The Process (How it works)

When a user accesses the library URL (e.g., `/hook/library`), the module follows this logic flow:

1.  **Incoming Request:** The module receives the HTTP request via its own registered hook.
2.  **Authentication Check:**
    - The module checks the configured `SecretsManagerID`.
    - It calls `SEC_IsPortalAuthenticated($instanceID)` to verify the user's session.
    - **If unauthorized:** The user is redirected to the Secrets Manager login portal.
    - **If authorized:** The process continues.
3.  **Data Retrieval:**
    - The module locates the Core WebHook Control instance (GUID `{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}`).
    - It retrieves the raw `Hooks` property (JSON) containing all registered paths and target IDs.
4.  **HTML Generation:**
    - The module constructs a complete HTML5 page with embedded CSS for styling.
    - It iterates through the list of hooks and generates `<a>` tags for each entry.
5.  **Output:** The generated HTML is sent back to the browser, displaying the list.

---

## 4. How to Use (Example)

### Prerequisite

- IP-Symcon 6.0 or higher.
- The **Secrets Manager** (Passkey) module must be installed and configured.

### Setup

1.  Install the **Webhook Library** module.
2.  Create an instance of **Webhook Library** (e.g., in a category named "System").
3.  In the configuration form, select your **Secrets Manager** instance in the dropdown menu.
4.  Click **Apply**.

### Usage

1.  Open your web browser.
2.  Navigate to: `http://<IP-Symcon-IP>:3777/hook/library`
    - _(Or use your Symcon Connect URL: `https://<xxx>.ipmagic.de/hook/library`)_
3.  **Login:** You will be prompted to authenticate using your Passkey/Biometrics via the Secrets Manager.
4.  **Browse:** Once logged in, you will see the list of all Webhooks.
5.  **Click:** Click any link to open that specific Webhook in a new tab.

---

## 5. Technical Details

- **Module Prefix:** `WHL`
- **WebHook URL:** `/hook/library`
- **Dependencies:** Requires `Secrets Manager` for authentication logic.
````
