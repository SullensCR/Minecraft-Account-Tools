# Minecraft-Account-Tools
A collection of tools that I use for account switching.

> [!WARNING]
> All these scripts were made with ChatGPT Codex and tested on _Python 3.14.6-2_ for Linux.

---
### Cookie to Access Token
**Usage:** 
Install dependencies: `python3 -m pip install -r requirements.txt`

Running: 
```bash
python3 ./script.py
```

After running the script a file dialog will ask you for a .txt file containing the cookie file in a Netscape/tab-separated (What most alt shops give you) and afterwards will show you information about the account.

The script displays the Minecraft name and UUID. It hides the access token by
default.
> Use the `--output` flag to show it and opionally provide a fiename to save the token to

```bash
python3 script.py "/full/path/to/cookies.txt" --output session.json
```

---

### Refresh Token to Access Token
**Usage:**

Running: 
```bash
python3 ./script.py
```

The script will ask you for a refresh token and if its valid it will authenticate with Microsoft and print the access token.

## Happy cheating!
