const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const bwipjs = require("bwip-js");
const PDFDocument = require("pdfkit");
const crypto = require("crypto");
const cors = require("cors");
const { Pool } = require("pg");
const process = require("node:process");
const dotenv = require("dotenv");

dotenv.config();

const app = express();

const multer = require("multer");
const noFileUpload = multer().none();
const fileUpload = multer().any();

const corsOpts = {
  origin: '*',

  methods: [
    'GET',
    'POST',
    'DELETE'
  ],

  allowedHeaders: [
    'Content-Type',
  ],
};

// Middleware
app.use(
  express.json(),
  cors(corsOpts),
);



// PostgreSQL Client Setup

const pool = new Pool({
  user: process.env.DATABASE_USER,
  host: "localhost",
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASSWORD,
  port: process.env.DATABASE_PORT,
});

// Helper Functions
const generateQrCode = async (text) => {
  return new Promise((resolve, reject) => {
    bwipjs.toBuffer(
      {
        bcid: "qrcode",
        text: text,
        scale: 3,
        height: 20,
        includetext: true,
        textxalign: "center",
      },
      (err, png) => {
        if (err) reject(err);
        else resolve(png);
      }
    );
  });
};

// generate ulid
const generateUlid = () => {
  return crypto.randomBytes(10).toString("hex");
};

// Fetch image from Cloudinary or any URL
const fetchImage = async (url) => {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Failed to fetch image: ${response.statusText}`);
  return Buffer.from(await response.arrayBuffer());
};


const generatePDF = async (username, qrcodeBuffer) => {
  return new Promise(async (resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', layout: 'portrait' });
    const chunks = [];

    doc.on('data', (chunk) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', (err) => reject(err));

    try {
      // Fetch the background image from the Cloudinary URL
      const bgImageBuffer = await fetchImage(process.env.PDF_BACKGROUND_IMAGE_URL);

      // Add the background image
      doc.image(bgImageBuffer, 0, 0, { width: doc.page.width, height: doc.page.height });

      // Add QR Code inside the white square
      doc.image(qrcodeBuffer, 100, 170, { width: 120, height: 140 },);

      // Add username on top of the QR Code
      doc.fontSize(24).fillColor('white').text(username, 300, 140, { align: 'center' });
      // add tan colour rectangle
      doc.rect(320, 165, 220, 30).fillAndStroke('#A07734', '#A07734');

      doc.end();
    } catch (error) {
      reject(error);
    }
  });
};

// Email Configuration
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  // secure: process.env.EMAIL_SECURE,
  auth: {
    user: process.env.EMAIL_ADDRESS,
    pass: process.env.EMAIL_PASSWORD,
  },
});

const sendEmail = async (email, pdfBuffer) => {
  await transporter.sendMail({
    from: process.env.EMAIL_ADDRESS,
    to: email,
    subject: "Your Event QrCode",
    text: "Please find your event qrcode attached.",
    attachments: [
      {
        filename: "qrcode.pdf",
        content: pdfBuffer,
      },
    ],
  });
};

// Auth Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header("Authorization").replace("Bearer ", "");
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [
      decoded._id,
    ]);
    const user = userResult.rows[0];

    if (!user) throw new Error();

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).send({ message: "Please authenticate." });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).send({ message: "Admin access only." });
  }
  next();
};

// API Routes
app.post("/api/auth/admin-login", noFileUpload, async (req, res) => {
  const { email, password } = req.body;
  try {
    const userResult = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    const user = userResult.rows[0];

    if (!user || user.role !== "admin") {
      return res.status(403).send({ message: "Access denied." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send({ message: "Invalid credentials." });
    }
    delete user.password;
    const token = jwt.sign(
      { _id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );
    res.send({ user, token });
  } catch (error) {
    res.status(500).send({ message: "Login failed." });
  }
});

app.post("/api/auth/logout", auth, async (req, res) => {
  try {
    req.token = null;
    res.status(200).send({ message: "Successfully logged out" });
  } catch (error) {
    res.status(500).send({ message: "Logout failed" });
  }
});

// Admin: Create new user with qrcode
app.post("/api/users", auth, isAdmin, noFileUpload, async (req, res) => {
  try {
    const { name, email } = req.body;
    const role = "customer";

    // Generate unique ID
    const id = generateUlid();

    // Check if user already exists
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    if (existingUser.rows.length > 0) {
      return res.status(400).send({ message: "User already exists" });
    }

    // Generate unique QR code
    const qrcode = crypto.randomBytes(16).toString("hex");

    // Insert user into PostgreSQL
    const result = await pool.query(
      "INSERT INTO users (id, name, email, role, qrcode, password) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
      [id, name, email, role, qrcode, ""]
    );

    const user = result.rows[0];

    // Generate QR code image
    const qrcodeBuffer = await generateQrCode(qrcode);

    // Generate PDF
    const pdfBuffer = await generatePDF(name, qrcodeBuffer);

    // Send email (Uncomment in production)
    await sendEmail(email, pdfBuffer);
    // await sendEmail(email, pdfBuffer);

    delete user.password;
    res.status(201).send(user);
  } catch (error) {
    res
      .status(400)
      .send({ message: "Error creating user", details: error.message });
  }
});

// Admin: Bulk create users
app.post("/api/users/bulk", auth, isAdmin, async (req, res) => {
  try {
    const { users } = req.body; // Array of {name, email}
    const createdUsers = [];

    for (const userData of users) {
      const qrcode = crypto.randomBytes(16).toString("hex");
      const result = await pool.query(
        "INSERT INTO users (name, email, role, qrcode) VALUES ($1, $2, $3, $4) RETURNING *",
        [userData.name, userData.email, userData.role || "customer", qrcode]
      );
      const user = result.rows[0];

      const qrcodeBuffer = await generateQrCode(qrcode);
      const pdfBuffer = await generatePDF(user, qrcodeBuffer);
      await sendEmail(userData.email, pdfBuffer);

      createdUsers.push(user);
    }

    res.status(201).send(createdUsers);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Admin: Verify qrcode
app.post("/api/verify/:qrcode", auth, fileUpload, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE qrcode = $1", [
      req.params.qrcode,
    ]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).send({ message: "QrCode not found" });
    }

    if (user.is_verified) {
      return res.status(400).send({ message: "QrCode already verified" });
    }

    // Update user's verification status
    await pool.query(
      "UPDATE users SET is_verified = true, verification_time = $1 WHERE qrcode = $2",
      [new Date(), req.params.qrcode]
    );

    delete user.password;
    res.status(200).send(user);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Admin: Get all users (excluding admins)
// sort by created date
app.get("/api/users", auth, isAdmin, async (req, res) => {
  const { page = 1, limit = 20, q = "" } = req.query;
  const offset = (page - 1) * limit;

  try {
    const result = await pool.query(
      `SELECT * FROM users 
       WHERE role != 'admin' 
       AND (name ILIKE $1 OR email ILIKE $1)
       ORDER BY id
       LIMIT $2 OFFSET $3`,
      [`%${q}%`, limit, offset]
    );

    const totalUsers = await pool.query(
      `SELECT COUNT(*) FROM users WHERE role != 'admin' AND (name ILIKE $1 OR email ILIKE $1)`,
      [`%${q}%`]
    );

    res.send({
      users: result.rows,
      total: parseInt(totalUsers.rows[0].count),
      current_page: parseInt(page),
      per_page: parseInt(limit),
    });
  } catch (error) {
    res.status(500).send(error);
  }
});

// Admin: Get stats for total users and verified users (excluding admins)
app.get("/api/stats", auth, isAdmin, async (req, res) => {
  try {
    const totalUsers = await pool.query(
      `SELECT COUNT(*) FROM users WHERE role != 'admin'`
    );
    const verifiedUsers = await pool.query(
      `SELECT COUNT(*) FROM users WHERE role != 'admin' AND is_verified = true`
    );

    res.send({
      total_users: parseInt(totalUsers.rows[0].count),
      verified_users: parseInt(verifiedUsers.rows[0].count),
    });
  } catch (error) {
    res.status(500).send({ error: "Failed to fetch stats." });
  }
});

// Download QR code for a specific user as PDF
app.get(
  "/api/users/:id/download-qrcode",
  auth,
  noFileUpload,
  async (req, res) => {
    try {
      // Fetch user by ID
      const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [
        req.params.id,
      ]);
      const user = userResult.rows[0];

      if (!user) {
        return res.status(404).send({ message: "User not found." });
      }

      // Generate QR code
      const qrcodeBuffer = await generateQrCode(user.qrcode);

      // Generate PDF with QR code
      const pdfBuffer = await generatePDF(user.name, qrcodeBuffer);

      // Set response headers for file download
      // res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Length", pdfBuffer.length);
      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=${user.name}_qrcode.pdf`
      );

      // Send PDF buffer as a downloadable file
      res.send(pdfBuffer);
    } catch (error) {
      res.status(500).send({ message: "Could not download QR code." });
    }
  }
);

// Verify user by ID
app.post("/api/users/:id/verify", auth, noFileUpload, async (req, res) => {
  try {
    // Fetch user by ID
    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [
      req.params.id,
    ]);
    const user = userResult.rows[0];

    if (!user) {
      return res.status(404).send({ message: "User not found." });
    }

    if (user.is_verified) {
      return res.status(400).send({ message: "User already verified." });
    }

    // Update verification status
    await pool.query(
      "UPDATE users SET is_verified = true, verification_time = $1 WHERE id = $2",
      [new Date(), req.params.id]
    );

    res.send({ success: true, message: "User verified successfully." });
  } catch (error) {
    res.status(500).send({ message: "Verification failed." });
  }
});


// Delete user by ID
app.delete("/api/users/:id", auth, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query("DELETE FROM users WHERE id = $1 RETURNING *", [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).send({ message: "User not found" });
    }

    res.status(200).send({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).send({ message: "Error deleting user" });
  }
});


const createUsersTable = async () => {
  try {
  await pool.query(`
   CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(32) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'customer',
    password VARCHAR(255) NOT NULL,
    qrcode VARCHAR(50),
    is_verified BOOLEAN DEFAULT FALSE,
    verification_time TIMESTAMP NULL
   );
  `);
    console.log('Users table created or already exists.');
  } catch (error) {
    console.error('Error creating users table:', error);
  }
};



const seedAdmins = async (admins) => {
  const admin = admins[0];

  // Check if admin already exists
  const result = await pool.query("SELECT * FROM users WHERE email = $1", [
    admin.email,
  ]);
  if (result.rows.length > 0) {
    console.log("Admin already exists. Skipping seed.");
    return;
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(admin.password, 10);

  // Seed admin if not present
  await pool.query(
    "INSERT INTO users (id, name, email, role, password) VALUES ($1, $2, $3, 'admin', $4)",
    [admin.id, admin.name, admin.email, hashedPassword]
  );
  console.log("Admin seeded successfully.");
};

// Execute once
(async () => {
  await createUsersTable();
  await seedAdmins([
    {
      id: generateUlid(),
      name: process.env.ADMIN_NAME,
      email: process.env.ADMIN_EMAIL,
      password: process.env.ADMIN_PASSWORD,
    },
  ]);
})();

// Example check
pool.connect((err) => {
  if (err) {
    console.error("Database connection message :", err.stack);
  } else {
    console.log("Connected to the database.");
  }
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
