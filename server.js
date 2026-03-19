const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { BrevoClient } = require('@getbrevo/brevo');
const db = require('./db');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

// ── Session ──────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// ── Brevo Email Setup (v5) ────────────────────────────────
const brevoClient = new BrevoClient({ apiKey: process.env.BREVO_API_KEY });

// ── Passport Google Strategy ─────────────────────────────
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const name = profile.displayName;
    const googleId = profile.id;

    const [rows] = await db.query('SELECT * FROM users WHERE google_id = ?', [googleId]);

    let user;
    if (rows.length > 0) {
      user = rows[0];
    } else {
      const [result] = await db.query(
        'INSERT INTO users (google_id, name, email) VALUES (?, ?, ?)',
        [googleId, name, email]
      );
      user = { id: result.insertId, name, email };
    }

    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);
  done(null, rows[0]);
});

// ── Helper: Generate OTP ──────────────────────────────────
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ── Routes ────────────────────────────────────────────────

// Google Login
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Google Callback → generate & send OTP
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?error=google_failed' }),
  async (req, res) => {
    try {
      const user = req.user;
      const otp = generateOTP();
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

      // Save OTP to DB
      await db.query(
        'INSERT INTO otp_codes (user_id, otp_code, expires_at) VALUES (?, ?, ?)',
        [user.id, otp, expiresAt]
      );

      // Send OTP email via Brevo v5
      const emailResult = await brevoClient.transactionalEmails.sendTransacEmail({
        subject: 'Your OTP Code',
        htmlContent: `
          <h2>Hello ${user.name}!</h2>
          <p>Your OTP code is:</p>
          <h1 style="letter-spacing:8px; color:#4F46E5">${otp}</h1>
          <p>This code expires in <strong>5 minutes</strong>.</p>
        `,
        sender: {
          name: 'Test Auth App',
          email: process.env.BREVO_SENDER_EMAIL
        },
        to: [{ email: user.email }]
      });

      console.log('📧 Email sent successfully:', emailResult);

      // Redirect to OTP page
      res.redirect(`${process.env.CLIENT_URL}/otp.html?userId=${user.id}&email=${encodeURIComponent(user.email)}`);
    } catch (err) {
      console.error('❌ Callback error:', err.message);
      res.status(500).send(`Error: ${err.message}`);
    }
  }
);

// Verify OTP
app.post('/verify-otp', async (req, res) => {
  const { userId, otp } = req.body;

  try {
    const [rows] = await db.query(
      `SELECT * FROM otp_codes 
       WHERE user_id = ? AND otp_code = ? AND used = FALSE AND expires_at > NOW()
       ORDER BY id DESC LIMIT 1`,
      [userId, otp]
    );

    if (rows.length === 0) {
      return res.json({ success: false, message: 'Invalid or expired OTP.' });
    }

    // Mark OTP as used
    await db.query('UPDATE otp_codes SET used = TRUE WHERE id = ?', [rows[0].id]);

    // Get user info
    const [userRows] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);

    res.json({ success: true, message: 'OTP verified!', user: userRows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// Status check
app.get('/me', (req, res) => {
  if (req.user) return res.json(req.user);
  res.json(null);
});

app.listen(3000, () => console.log('Server running at http://localhost:3000'));