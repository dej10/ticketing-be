const express = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer')
const bwipjs = require('bwip-js')
const crypto = require('crypto')
const cors = require('cors')
const {Pool} = require('pg')
const Papa = require('papaparse')
const process = require('node:process')
const fs = require('fs')
const path = require('path')
const fontkit = require('@pdf-lib/fontkit')
const {PDFDocument, rgb} = require('pdf-lib')
const dotenv = require('dotenv')
const JSZip = require('jszip')

dotenv.config()

const app = express()

const multer = require('multer')
const noFileUpload = multer().none()
const fileUpload = multer().any()

const corsOpts = {
  origin: ['http://localhost:3002', 'https://ticketing-fe.pages.dev', 'https://staging.ticketing-fe.pages.dev/'],

  methods: ['GET', 'POST', 'DELETE'],

  allowedHeaders: ['Content-Type', 'Authorization'],

  credentials: true,
}

// Middleware
app.use(express.json(), cors(corsOpts), function (req, res, next) {
  const allowedOrigins = ['http://localhost:3002', 'https://ticketing-fe.pages.dev']
  const origin = req.headers.origin
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin)
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  res.setHeader('Access-Control-Allow-Credentials', 'true')
  next()
})

// PostgreSQL Client Setup
const pool = new Pool({
  user: process.env.DATABASE_USER,
  host: 'localhost',
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASSWORD,
  port: process.env.DATABASE_PORT,
})

// Helper Functions
const generateQrCode = async (text) => {
  return new Promise((resolve, reject) => {
    bwipjs.toBuffer(
      {
        bcid: 'qrcode',
        text: text,
        scale: 3,
        height: 20,
        includetext: true,
        textxalign: 'center',
      },
      (err, png) => {
        if (err) reject(err)
        else resolve(png)
      }
    )
  })
}

// generate ulid
const generateUlid = () => {
  return crypto.randomBytes(10).toString('hex')
}

const generatePDF = async (username, qrcodeBuffer) => {
  try {
    const pdfPath = path.resolve(__dirname, './assets/access_card.pdf')
    const existingPdfBytes = fs.readFileSync(pdfPath)

    const pdfDoc = await PDFDocument.load(existingPdfBytes)
    pdfDoc.registerFontkit(fontkit)

    const qrImage = await pdfDoc.embedPng(qrcodeBuffer)
    const fontPath = path.resolve(__dirname, './assets/fonts/PlayfairDisplay.ttf')
    const fontBytes = fs.readFileSync(fontPath)
    const playfairFont = await pdfDoc.embedFont(fontBytes)

    const pages = pdfDoc.getPages()
    const firstPage = pages[0]

    firstPage.drawImage(qrImage, {x: 170, y: 210, width: 240, height: 240})
    username = username.charAt(0).toUpperCase() + username.slice(1)

    firstPage.drawText(username, {
      x: 600,
      y: 400,
      size: 34,
      font: playfairFont,
      color: rgb(1, 1, 1),
    })

    const pdfBuffer = await pdfDoc.save()
    return pdfBuffer // Return the PDF buffer
  } catch (error) {
    console.error('Error modifying PDF:', error)
  }
}

// Email Configuration
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  auth: {
    user: 'apikey',
    pass: process.env.EMAIL_PASSWORD,
  },
})

const sendEmail = async (email, pdfBuffer, name) => {
  await transporter.sendMail({
    from: `${process.env.EMAIL_FROM_NAME} <${process.env.EMAIL_ADDRESS}>`,
    to: email,
    subject: 'Your Invite to our Wedding',
    text: `
    Dear ${name}, \n
    Thank you for RSVPing to our wedding!  \n
    Please find your official invitation attached to this email. \n
    Please present the QR code in the invitation for scanning at the door of the event for check-in. \n
     `,
    attachments: [
      {
        filename: `Access Card for ${name}.pdf`,
        content: pdfBuffer,
      },
    ],
  })
}

// Auth Middle ware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '')
    const decoded = jwt.verify(token, process.env.JWT_SECRET)

    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [decoded._id])
    const user = userResult.rows[0]

    if (!user) throw new Error()

    req.user = user
    req.token = token
    next()
  } catch (error) {
    res.status(401).send({message: 'Please authenticate.'})
  }
}

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send({message: 'Admin access only.'})
  }
  next()
}

// API Routes
app.post('/api/auth/admin-login', noFileUpload, async (req, res) => {
  const {email, password} = req.body
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email])
    const user = userResult.rows[0]

    if (!user || user.role !== 'admin') {
      return res.status(403).send({message: 'Access denied.'})
    }

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.status(400).send({message: 'Invalid credentials.'})
    }
    delete user.password
    const token = jwt.sign({_id: user.id, role: user.role}, process.env.JWT_SECRET, {expiresIn: '24h'})
    res.send({user, token})
  } catch (error) {
    res.status(500).send({message: 'Login failed.'})
  }
})

app.post('/api/auth/logout', auth, async (req, res) => {
  try {
    req.token = null
    res.status(200).send({message: 'Successfully logged out'})
  } catch (error) {
    res.status(500).send({message: 'Logout failed'})
  }
})

// Admin: Create new user with qrcode
app.post('/api/users', auth, isAdmin, noFileUpload, async (req, res) => {
  try {
    const {name, email} = req.body
    const role = 'customer'

    // Generate unique ID
    const id = generateUlid()

    // Check if user already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email])
    if (existingUser.rows.length > 0) {
      return res.status(400).send({message: 'User already exists'})
    }

    // Generate unique QR code
    const qrcode = crypto.randomBytes(16).toString('hex')

    // Insert user into PostgreSQL
    const result = await pool.query(
      'INSERT INTO users (id, name, email, role, qrcode, password) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [id, name, email, role, qrcode, '']
    )

    const user = result.rows[0]

    delete user.password
    res.status(201).send(user)
  } catch (error) {
    res.status(400).send({message: 'Error creating user', details: error.message})
  }
})

// Admin: Bulk upload users with CSV file
app.post('/api/users/bulk', auth, isAdmin, fileUpload, async (req, res) => {
  try {
    if (!req.files || !req.files.length) {
      return res.status(400).send({message: 'Please upload a CSV file'})
    }

    const file = req.files[0]
    const csvContent = file.buffer.toString('utf-8')

    const results = await new Promise((resolve, reject) => {
      Papa.parse(csvContent, {
        header: true,
        skipEmptyLines: true,
        transformHeader: (header) => header.trim(),
        complete: (results) => resolve(results),
        error: (error) => reject(error),
      })
    })

    const createdUsers = []
    const skippedUsers = []

    // Get all existing users for comparison
    const existingUsersResult = await pool.query('SELECT name, email FROM users WHERE role = $1', ['customer'])
    const existingUsers = existingUsersResult.rows
    const existingSet = new Set(
      existingUsers.map((user) => `${user.name.toLowerCase()}${user.email ? `|${user.email.toLowerCase()}` : ''}`)
    )

    for (const row of results.data) {
      try {
        const firstName = row['First Name']?.trim() || ''
        const lastName = row['Last Name']?.trim() || ''

        if (!firstName && !lastName) continue

        const name = [firstName, lastName].filter(Boolean).join(' ')
        const email = row['Email'] ? row['Email'].trim() : null

        const comparisonKey = `${name.toLowerCase()}${email ? `|${email.toLowerCase()}` : ''}`

        if (existingSet.has(comparisonKey)) {
          skippedUsers.push({name, email, reason: 'User already exists'})
          continue
        }

        const qrcode = crypto.randomBytes(16).toString('hex')
        const id = generateUlid()

        const result = await pool.query(
          'INSERT INTO users (id, name, email, role, qrcode, password) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
          [id, name, email, 'customer', qrcode, '']
        )

        const user = result.rows[0]

        delete user.password
        createdUsers.push(user)
      } catch (error) {
        console.error(`Error processing row:`, row, error)
        continue
      }
    }

    res.status(201).send({
      message: 'Bulk upload completed',
      created: createdUsers,
      skipped: skippedUsers,
      summary: {
        total: results.data.length,
        successful: createdUsers.length,
        skipped: skippedUsers.length,
      },
    })
  } catch (error) {
    console.error('Bulk upload error:', error)
    res.status(400).send({
      message: 'Error processing bulk upload',
      error: error.message,
    })
  }
})

// Admin: Download all invites as a zip file
app.get('/api/users/download-all-invites', auth, isAdmin, async (req, res) => {
  try {
    const zip = new JSZip()

    const result = await pool.query(
      `
      SELECT * FROM users 
      WHERE role = $1 
      AND (invite_downloaded = FALSE OR invite_downloaded IS NULL)
    `,
      ['customer']
    )

    const users = result.rows

    if (users.length === 0) {
      return res.status(200).send({
        message: 'No new invites to download',
      })
    }

    const pdfsFolder = zip.folder('invites')

    const processed = {
      successful: [],
      failed: [],
    }

    for (const user of users) {
      try {
        const qrcodeBuffer = await generateQrCode(user.qrcode)
        const pdfBuffer = await generatePDF(user.name, qrcodeBuffer)
        const safeFileName = `${user.name.replace(/[/\\?%*:|"<>]/g, '-')}.pdf`
        pdfsFolder.file(safeFileName, pdfBuffer)
        processed.successful.push(user.id)
      } catch (error) {
        console.error(`Error generating PDF for user ${user.name}:`, error)
        processed.failed.push(user.id)
        continue
      }
    }

    const zipBuffer = await zip.generateAsync({
      type: 'nodebuffer',
      compression: 'DEFLATE',
      compressionOptions: {
        level: 9, // maximum compression
      },
    })

    if (processed.successful.length > 0) {
      await pool.query(
        `
        UPDATE users 
        SET invite_downloaded = TRUE,
            invite_downloaded_at = NOW()
        WHERE id = ANY($1)
      `,
        [processed.successful]
      )
    }

    // Set headers for file download
    res.setHeader('Content-Type', 'application/zip')
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="new-invites-${new Date().toISOString().split('T')[0]}.zip"`
    )
    res.setHeader('Content-Length', zipBuffer.length)
    res.send(zipBuffer)
  } catch (error) {
    console.error('Error generating zip file:', error)
    res.status(500).send({
      message: 'Error generating zip file',
      error: error.message,
    })
  }
})

// Admin: Send invites to all users
app.post('/api/users/send-all-invites', auth, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT * FROM users 
      WHERE role = $1 
      AND email IS NOT NULL 
      AND (invite_sent = FALSE OR invite_sent IS NULL)
    `,
      ['customer']
    )

    const users = result.rows

    if (users.length === 0) {
      return res.status(200).send({
        message: 'No new invites to send',
        summary: {
          total: 0,
          successful: 0,
          failed: 0,
        },
        results: {
          successful: [],
          failed: [],
        },
      })
    }

    const results = {
      successful: [],
      failed: [],
    }

    for (const user of users) {
      try {
        const qrcodeBuffer = await generateQrCode(user.qrcode)
        const pdfBuffer = await generatePDF(user.name, qrcodeBuffer)
        await sendEmail(user.email, pdfBuffer, user.name)

        await pool.query(
          `
          UPDATE users 
          SET invite_sent = TRUE, 
              invite_sent_at = NOW() 
          WHERE id = $1
        `,
          [user.id]
        )

        results.successful.push({
          id: user.id,
          name: user.name,
          email: user.email,
        })
      } catch (error) {
        console.error(`Error sending invite to ${user.email}:`, error)
        results.failed.push({
          id: user.id,
          name: user.name,
          email: user.email,
          error: error.message,
        })
      }
    }

    res.status(200).send({
      message: 'Completed sending invites',
      summary: {
        total: users.length,
        successful: results.successful.length,
        failed: results.failed.length,
      },
      results,
    })
  } catch (error) {
    console.error('Error sending invites:', error)
    res.status(500).send({
      message: 'Error sending invites',
      error: error.message,
    })
  }
})

// Admin: Verify qrcode
app.post('/api/verify/:qrcode', auth, fileUpload, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE qrcode = $1', [req.params.qrcode])
    const user = result.rows[0]

    if (!user) {
      return res.status(404).send({message: 'QrCode not found'})
    }

    if (user.is_verified) {
      return res.status(400).send({message: 'QrCode already verified'})
    }

    // Update user's verification status
    await pool.query('UPDATE users SET is_verified = true, verification_time = $1 WHERE qrcode = $2', [
      new Date(),
      req.params.qrcode,
    ])

    delete user.password
    res.status(200).send(user)
  } catch (error) {
    res.status(400).send(error)
  }
})

// Admin: Get all users (excluding admins)
// sort by created date
app.get('/api/users', auth, isAdmin, async (req, res) => {
  const {page = 1, limit = 20, q = ''} = req.query
  const offset = (page - 1) * limit

  try {
    const result = await pool.query(
      `SELECT * FROM users 
       WHERE role != 'admin' 
       AND (name ILIKE $1 OR email ILIKE $1)
       ORDER BY id
       LIMIT $2 OFFSET $3`,
      [`%${q}%`, limit, offset]
    )

    const totalUsers = await pool.query(
      `SELECT COUNT(*) FROM users WHERE role != 'admin' AND (name ILIKE $1 OR email ILIKE $1)`,
      [`%${q}%`]
    )

    res.send({
      users: result.rows,
      total: parseInt(totalUsers.rows[0].count),
      current_page: parseInt(page),
      per_page: parseInt(limit),
    })
  } catch (error) {
    res.status(500).send(error)
  }
})

// Admin: Get stats for total users and verified users (excluding admins)
app.get('/api/stats', auth, isAdmin, async (req, res) => {
  try {
    const totalUsers = await pool.query(`SELECT COUNT(*) FROM users WHERE role != 'admin'`)
    const verifiedUsers = await pool.query(`SELECT COUNT(*) FROM users WHERE role != 'admin' AND is_verified = true`)

    res.send({
      total_users: parseInt(totalUsers.rows[0].count),
      verified_users: parseInt(verifiedUsers.rows[0].count),
    })
  } catch (error) {
    res.status(500).send({error: 'Failed to fetch stats.'})
  }
})

app.get('/api/users/:id/download-qrcode', auth, noFileUpload, async (req, res) => {
  try {
    // Fetch user by ID
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id])
    const user = userResult.rows[0]

    if (!user) {
      return res.status(404).send({message: 'User not found.'})
    }

    // Generate QR code buffer
    const qrcodeBuffer = await generateQrCode(user.qrcode)

    // Generate PDF with QR code
    const pdfBuffer = await generatePDF(user.name, qrcodeBuffer)

    // Set response headers for file download
    res.setHeader('Content-Type', 'application/pdf')
    res.setHeader('Content-Length', pdfBuffer.length)
    res.setHeader('Content-Disposition', `attachment; filename="${user.name}_qrcode.pdf"`)

    // Send PDF buffer as a downloadable file
    res.end(pdfBuffer) // Use res.end() to send the buffer properly
  } catch (error) {
    console.error('Error generating or downloading PDF:', error)
    res.status(500).send({message: 'Could not download QR code.'})
  }
})

// Verify user by ID
app.post('/api/users/:id/verify', auth, noFileUpload, async (req, res) => {
  try {
    // Fetch user by ID
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id])
    const user = userResult.rows[0]

    if (!user) {
      return res.status(404).send({message: 'User not found.'})
    }

    if (user.is_verified) {
      return res.status(400).send({message: 'User already verified.'})
    }

    // Update verification status
    await pool.query('UPDATE users SET is_verified = true, verification_time = $1 WHERE id = $2', [
      new Date(),
      req.params.id,
    ])

    res.send({success: true, message: 'User verified successfully.'})
  } catch (error) {
    res.status(500).send({message: 'Verification failed.'})
  }
})

// Delete user by ID
app.delete('/api/users/:id', auth, isAdmin, async (req, res) => {
  try {
    const {id} = req.params
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id])

    if (result.rowCount === 0) {
      return res.status(404).send({message: 'User not found'})
    }

    res.status(200).send({message: 'User deleted successfully'})
  } catch (error) {
    res.status(500).send({message: 'Error deleting user'})
  }
})

const addInviteDownloadColumn = async () => {
  try {
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS invite_downloaded BOOLEAN DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS invite_downloaded_at TIMESTAMP;
    `)
    console.log('Added invite download tracking columns')
  } catch (error) {
    console.error('Error adding invite download tracking columns:', error)
  }
}

const addInviteSentColumn = async () => {
  try {
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS invite_sent BOOLEAN DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS invite_sent_at TIMESTAMP;
    `)
    console.log('Added invite tracking columns')
  } catch (error) {
    console.error('Error adding invite tracking columns:', error)
  }
}

const createUsersTable = async () => {
  try {
    await pool.query(`
   CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(32) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE,
    role VARCHAR(50) NOT NULL DEFAULT 'customer',
    password VARCHAR(255) NOT NULL,
    qrcode VARCHAR(50),
    is_verified BOOLEAN DEFAULT FALSE,
    verification_time TIMESTAMP NULL
   );
  `)
    console.log('Users table created or already exists.')
  } catch (error) {
    console.error('Error creating users table:', error)
  }
}

const seedAdmins = async (admins) => {
  const admin = admins[0]

  // Check if admin already exists
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [admin.email])
  if (result.rows.length > 0) {
    console.log('Admin already exists. Skipping seed.')
    return
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(admin.password, 10)

  // Seed admin if not present
  await pool.query("INSERT INTO users (id, name, email, role, password) VALUES ($1, $2, $3, 'admin', $4)", [
    admin.id,
    admin.name,
    admin.email,
    hashedPassword,
  ])
  console.log('Admin seeded successfully.')
}

// Execute once
;(async () => {
  await createUsersTable()
  await addInviteDownloadColumn()
  await addInviteSentColumn()
  await seedAdmins([
    {
      id: generateUlid(),
      name: process.env.ADMIN_NAME,
      email: process.env.ADMIN_EMAIL,
      password: process.env.ADMIN_PASSWORD,
    },
  ])
})()

// Example check
pool.connect((err) => {
  if (err) {
    console.error('Database connection message :', err.stack)
  } else {
    console.log('Connected to the database.')
  }
})

// Start server
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
