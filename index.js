const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const app = express();
const port = 3000;

// Middleware to parse JSON request bodies
app.use(bodyParser.json());

// Encryption function
const encryptSymmetric = (key, plaintext) => {
  const iv = crypto.randomBytes(12).toString("base64");
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    Buffer.from(key, "base64"),
    Buffer.from(iv, "base64")
  );
  let ciphertext = cipher.update(JSON.stringify(plaintext), "utf8", "base64");
  ciphertext += cipher.final("base64");
  const tag = cipher.getAuthTag();

  return { ciphertext, iv, tag };
};

// Decryption function
const decryptSymmetric = (key, ciphertext, iv, tag) => {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(key, "base64"),
    Buffer.from(iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(tag));

  let plaintext = decipher.update(ciphertext, "base64", "utf8");
  plaintext += decipher.final("utf8");

  return JSON.parse(plaintext);
};

// Route to decrypt ciphertext
app.post("/decrypt", (req, res) => {
  const { key, ciphertext, iv, tag } = req.body;

  if (!key || !ciphertext || !iv || !tag) {
    return res.status(400).json({ error: "Missing key, ciphertext, iv, or tag in request body" });
  }

  try {
    const plaintext = decryptSymmetric(key, ciphertext, iv, tag);
    res.json({ plaintext });
  } catch (error) {
    res.status(500).json({ error: "Decryption failed" });
  }
});

// Route to encrypt plaintext
app.post("/encrypt", (req, res) => {
  const { plaintext } = req.body;

  if (!plaintext) {
    return res.status(400).json({ error: "Plaintext data is missing in the request body" });
  }

  const key = crypto.randomBytes(32).toString("base64");

  const { ciphertext, iv, tag } = encryptSymmetric(key, plaintext);

  res.json({ ciphertext, iv, tag, key });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
