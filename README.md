# Majik Blob

**Majik Blob** is a lightweight JavaScript/TypeScript library for **encrypting and decrypting files (Blobs)** securely.  
It’s ideal for scenarios where you want to **store files in cloud storage or deliver files** but prevent direct access or downloads without the correct key.

---

### Live Demo

[![Majik Blob Thumbnail](https://www.thezelijah.world/_next/static/media/WA_Tools_Security_MajikBlob.ace9d387.webp)](https://www.thezelijah.world/tools/security-majik-blob)

> Click the image to try the smart tax assistant.

---

## ✨ Features

- 🔐 Encrypt **any file type** (images, audio, video, 3D models, documents, etc.)
- 📦 Returns a single encrypted Blob (`.mjkb`) with metadata for integrity verification
- 🧾 Preserves original MIME type & file extension
- 🧪 Includes tamper detection and password verification
- 🔁 Fully reversible with the correct key and RQX
- ⚡ Perfect for **obfuscating files stored on cloud storage or S3**
- 🌐 Browser-first, TypeScript-friendly

---

##  [Full API Docs](https://www.thezelijah.word/tools/security-majik-blob/docs)
---

## 📦 Installation

```bash
npm i @thezelijah/majik-blob
```

---

## Usage

### Generate a Key
Encrypts the file and returns a .mjkb Blob.
Majik Blob uses a password and an internal RQX key for encryption. Generate a key securely before encrypting:
```bash
import { MajikBlob } from "@thezelijah/majik-blob";
const { key, rqx } = MajikBlob.generateKey(32); // 32-character password
```


### Encrypting Files
```bash
import { MajikBlob } from "@thezelijah/majik-blob";
import { downloadBlob } from "@thezelijah/majik-blob/utils";

const file = new File(["Hello world"], "example.txt", { type: "text/plain" });

const majik = new MajikBlob(key, file);
const encryptedBlob = await majik.getEncryptedBlob(rqx);

// Save or upload the encrypted file
downloadBlob(encryptedBlob, "mjkb", "example");
```


### Decrypting Files
Decrypts a .mjkb Blob and restores the original file.
```bash
import { MajikBlob } from "@thezelijah/majik-blob";

const decrypted = await MajikBlob.decryptEncryptedBlob(encryptedBlob, key, rqx);

console.log(decrypted.data);       // Restored Blob
console.log(decrypted.type);       // Original MIME type
console.log(decrypted.extension);  // Original file extension
```


### Reading File Extension Without Decryption
Reads the original file extension without decrypting the file.
```bash
const extension = await MajikBlob.getEncryptedFileExtension(encryptedBlob);
console.log(extension); // e.g. "glb", "mp3", "png"
```

---

### Use Cases

- Secure file uploads before storing in cloud storage
- Obfuscated delivery of downloadable assets
- Protecting media files (audio, video, 3D models)
- Client-side encryption for creative tools
- Controlled-access file distribution systems
- DRM-adjacent workflows without heavy infrastructure

### Best Practices

- Use strong, unique passwords for each file.
- Store un-hashed password/key in environment variables to prevent tampering.
- Majik Blob is ideal for obfuscating files in storage; files cannot be opened without the correct key.
- Always verify the key before decrypting to avoid corrupted files.
- For large files, encryption and decryption may take longer—be patient.

**Important:**
Always store the un-hashed encryption key and RQX in environment variables to prevent tampering and accidental exposure.


## Contributing

Contributions, bug reports, and suggestions are welcome! Feel free to fork and open a pull request.

---

## License

[ISC](LICENSE) — free for personal and commercial use.

---

## Author

Made with 💙 by [@thezelijah](https://github.com/thezelijah)


## About the Developer

- **Developer**: Josef Elijah Fabian  
- **GitHub**: [https://github.com/jedlsf](https://github.com/jedlsf)  
- **Project Repository**: [https://github.com/jedlsf/majik-blob](https://github.com/jedlsf/majik-blob)  

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)  
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)  

---
