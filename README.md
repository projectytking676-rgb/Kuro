# KURO PANEL — PythonAnywhere deployment

## 0. Localhost test (before publishing)

### Windows
1. Install Python 3.10+.
2. Open Command Prompt inside the extracted `kuro_panel` folder.
3. Run:
   ```bat
   py -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   set KURO_SECRET_KEY=replace-this-with-a-long-random-secret
   python create_admin.py
   python app.py
   ```
4. Open `http://127.0.0.1:5000` in your browser.

### Android / Termux or Linux
```bash
pkg install python -y   # Termux only; on Linux use your package manager
cd kuro_panel
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export KURO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python create_admin.py
python app.py
```
Open `http://127.0.0.1:5000` on the same device. For access from another device on the same Wi-Fi, run with `app.run(host="0.0.0.0", port=5000)` and use the host computer's LAN IP. Do not expose the Flask development server directly to the public internet.

`run_local.bat` and `run_local.sh` are convenience launch scripts. Set `KURO_SECRET_KEY` before running them.

## Real public hosting
Localhost is only accessible on the device/computer running the app. It is not a public website. To make it public, deploy the same project to PythonAnywhere (steps below) or another Flask-compatible host, configure HTTPS, set a private secret key in the host's environment/WSGI configuration, and point Sketchware to the public HTTPS URL. Do not use `127.0.0.1` or `localhost` inside the APK: on a user's phone, those addresses refer to that phone, not your server.


## Included
- Black + Gold admin website (login, dashboard, key manager, online controls)
- SQLite database
- Unlimited key creation (limited only by hosting storage)
- Optional pre-bound Device ID, or first-use device binding
- Enable/disable/delete keys and optional expiry date
- Public JSON API for verification, online update switch, maintenance switch and version check
- Sketchware Java integration example below

## 1. Local setup
Use Python 3.10+.

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

Set a long random secret before running:
```bash
export KURO_SECRET_KEY="paste-a-long-random-secret-here"
python create_admin.py
python app.py
```
On Windows PowerShell use `$env:KURO_SECRET_KEY="..."`.

Create an admin username and a strong password of at least 12 characters. Do not share the admin login.

## 2. PythonAnywhere deployment
1. Upload and extract `kuro_panel.zip` into `/home/YOUR_USERNAME/kuro_panel`.
2. Open a Bash console:
   ```bash
   cd ~/kuro_panel
   python3.10 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Generate a secret:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
4. Create the admin account:
   ```bash
   export KURO_SECRET_KEY='YOUR_LONG_RANDOM_SECRET'
   python create_admin.py
   ```
5. In PythonAnywhere **Web** tab, create a Flask web app using manual configuration and your chosen Python version.
6. Set the WSGI file to import the app. Edit `wsgi.py`: replace `YOUR_PYTHONANYWHERE_USERNAME` and `REPLACE_WITH_A_LONG_RANDOM_SECRET`. Use the same secret you generated.
7. In the Web tab, set the virtualenv path to `/home/YOUR_USERNAME/kuro_panel/venv`.
8. Reload the web app. Use HTTPS and keep the admin password private.

For persistent database storage, keep `kuro.db` in your project folder or set `KURO_DB_PATH` to a persistent path under your home directory. Back up this file regularly.

## 3. API contract

### Verify a license
`POST /api/v1/verify` with JSON:
```json
{"key":"KURO-EXAMPLEKEY","device_id":"ANDROID-DEVICE-ID"}
```
Success:
```json
{"ok":true,"message":"License verified","device_bound":true}
```
A key created with a Device ID only works on that Device ID. A key created without one is bound to the first Device ID that successfully verifies it.

### Read remote settings
`GET /api/v1/config`

### Check for an app update
`GET /api/v1/update?version=1.0.0`

The API does not silently install updates. The app should show an update prompt and let the user choose whether to open the HTTPS download URL.

## 4. Sketchware / Java integration

Replace `https://YOUR-SITE.pythonanywhere.com` with your actual domain. Call network code on a background thread, not the UI thread. Add INTERNET permission to the manifest.

```java
import android.os.Handler;
import android.os.Looper;
import org.json.JSONObject;
import java.io.*;
import java.net.*;

private final Handler mainHandler = new Handler(Looper.getMainLooper());

private void verifyKuroKey(String key, String deviceId) {
    new Thread(() -> {
        HttpURLConnection conn = null;
        try {
            URL url = new URL("https://YOUR-SITE.pythonanywhere.com/api/v1/verify");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");

            JSONObject body = new JSONObject();
            body.put("key", key);
            body.put("device_id", deviceId);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.toString().getBytes("UTF-8"));
            }

            int code = conn.getResponseCode();
            InputStream stream = (code >= 200 && code < 300)
                    ? conn.getInputStream() : conn.getErrorStream();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] data = new byte[1024];
            int n;
            while ((n = stream.read(data)) != -1) buffer.write(data, 0, n);
            JSONObject result = new JSONObject(buffer.toString("UTF-8"));
            boolean ok = result.optBoolean("ok", false);
            String message = result.optString("message", "Unknown response");

            mainHandler.post(() -> {
                if (ok) {
                    // Replace with your Sketchware success action.
                    // Example: show success dialog / open your app's home screen.
                } else {
                    // Show message to user; do not bypass server verification.
                }
            });
        } catch (Exception e) {
            mainHandler.post(() -> {
                // Show a network error message.
            });
        } finally {
            if (conn != null) conn.disconnect();
        }
    }).start();
}
```

### Online Update switch + button
The admin's switch controls `/api/v1/config`. In Sketchware, call this when the app opens and when the refresh/update button is pressed:

```java
private void loadKuroConfig() {
    new Thread(() -> {
        HttpURLConnection conn = null;
        try {
            URL url = new URL("https://YOUR-SITE.pythonanywhere.com/api/v1/config");
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            JSONObject cfg;
            try (InputStream in = conn.getInputStream();
                 ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                byte[] b = new byte[1024]; int n;
                while ((n = in.read(b)) != -1) out.write(b, 0, n);
                cfg = new JSONObject(out.toString("UTF-8"));
            }
            boolean updateEnabled = cfg.optBoolean("online_update", false);
            boolean maintenance = cfg.optBoolean("maintenance", false);
            String latestVersion = cfg.optString("latest_version", "");
            String updateUrl = cfg.optString("update_url", "");
            String message = cfg.optString("update_message", "");

            mainHandler.post(() -> {
                // Set your Sketchware Switch checked state from updateEnabled.
                // If maintenance is true, show a maintenance notice.
                // Keep updateUrl for the Update button.
            });
        } catch (Exception e) {
            mainHandler.post(() -> {
                // Show "Unable to connect" and allow retry.
            });
        } finally {
            if (conn != null) conn.disconnect();
        }
    }).start();
}
```

Example button action after config has been loaded:
```java
if (updateEnabled && updateUrl.startsWith("https://")) {
    Intent browser = new Intent(Intent.ACTION_VIEW, Uri.parse(updateUrl));
    startActivity(browser);
} else {
    Toast.makeText(this, "No update available", Toast.LENGTH_SHORT).show();
}
```

Use your own app version string in `/api/v1/update?version=YOUR_CURRENT_VERSION` to compare versions. Add:
```xml
<uses-permission android:name="android.permission.INTERNET" />
```

## Security notes
- This is a starter project. Use HTTPS only.
- Keep `KURO_SECRET_KEY`, the admin password and database backups private.
- Do not put the admin password or Flask secret in the Android app.
- Public verification endpoints can be called by anyone; use HTTPS, monitor abuse, and add stronger rate limiting / CAPTCHA if exposed publicly.
- Device IDs are identifiers, not proof of a person's identity. Avoid collecting unnecessary personal data.
- The sample uses a simple first-successful-use device binding; provide a controlled admin reset workflow before using it for production.


## GitHub + real public deployment (Render Free)

1. Create a GitHub repository (keep it private if you do not want the source code public).
2. Upload the contents of this project folder to the repository root. Do not upload `venv/`, `kuro.db`, or any `.env` file.
3. On Render, choose **New → Web Service**, connect GitHub, and select the repository.
4. Set:
   - Runtime: Python
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
   - Instance type: Free
5. Add environment variables in Render:
   - `KURO_SECRET_KEY`: a long random secret (generate privately; never commit it)
   - `KURO_ADMIN_USERNAME`: `PROJECT` (default if omitted)
   - `KURO_ADMIN_PASSWORD`: choose a strong password (12+ characters). Do not use `YT` as a public admin password because it is too short and easy to guess.
6. Deploy. The first startup creates the initial admin if the database has no admin yet. Remove the bootstrap admin environment variables after confirming the first login, or rotate the password before sharing the site.
7. Open the Render-provided `https://...onrender.com` URL. Use this HTTPS URL as the API base in Sketchware.

**Important free-tier data warning:** This starter version stores license records in SQLite. Render Free web services have ephemeral filesystems; local SQLite records can disappear after spin-down, restart, or redeploy. Use this deployment only for a UI/API test until the project is migrated to a persistent external database. Do not store important customer licenses in this SQLite version on Render Free. Free Render Postgres currently has its own expiry/backup limitations; check the current provider terms before relying on it for long-term data.
