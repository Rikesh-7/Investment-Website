require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");

const app = express();

/* ========== MIDDLEWARE ========== */
app.use(cors());
app.use(bodyParser.json());

/* ========== DATABASE ========== */
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err.message);
    process.exit(1);
  }
  console.log("✅ Connected to the SQL database");
});

/* ========== SIGNUP ========== */
app.post("/api/signup", async (req, res) => {
  const { user_name, email, password } = req.body;

  if (!user_name || !email || !password) {
    return res.status(400).json({ success: false, message: "All fields required" });
  }

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, users) => {
    if (users.length > 0) {
      return res.status(400).json({ success: false, message: "Email exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO users (user_name, email, password) VALUES (?, ?, ?)",
      [user_name, email, hashed],
      () => res.json({ success: true })
    );
  });
});

/* ========== LOGIN ========== */
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, rows) => {
    if (!rows.length) {
      return res.status(401).json({ success: false });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ success: false });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        user_name: user.user_name,
        email: user.email,
      },
    });
  });
});

/* ========== GET PROFILE ========== */
app.get("/api/profile/:id", (req, res) => {
  db.query(
    "SELECT dob, location, pan_number, aadhaar_number FROM users WHERE id = ?",
    [req.params.id],
    (err, rows) => res.json(rows[0] || {})
  );
});

/* ========== UPDATE PROFILE ========== */
app.put("/api/profile/:id", (req, res) => {
  const { dob, location, pan_number, aadhaar_number } = req.body;

  db.query(
    "UPDATE users SET dob=?, location=?, pan_number=?, aadhaar_number=? WHERE id=?",
    [dob, location, pan_number, aadhaar_number, req.params.id],
    () => res.json({ success: true })
  );
});

/* ========== SERVER ========== */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);