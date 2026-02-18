const express = require("express");

const nodemailer = require("nodemailer");
const cron = require("node-cron");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(express.json());

// ============================================================
// DATABASE CONNECTION
// ============================================================
// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer storage using Cloudinary
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "tcet-onboarding",
    allowed_formats: ["jpg", "jpeg", "png", "pdf"],
    resource_type: "auto",
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("❌ MongoDB Error:", err));

// ============================================================
// MODELS
// ============================================================

// USER MODEL
const userSchema = new mongoose.Schema({
  name:     { type: String, required: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role:     { type: String, enum: ["student", "admin"], default: "student" },
  studentId:{ type: String },
  branch:   { type: String },
  year:     { type: String },
  phone:    { type: String },
  createdAt:{ type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);

// CHECKLIST ITEM MODEL
const checklistSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title:    { type: String, required: true },
  category: { type: String, required: true },
  status:   { type: String, enum: ["pending", "done", "locked"], default: "pending" },
  priority: { type: String, enum: ["high", "medium", "low"], default: "medium" },
  due:      { type: String },
  updatedAt:{ type: Date, default: Date.now },
});
const Checklist = mongoose.model("Checklist", checklistSchema);

// DOCUMENT MODEL
const documentSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  name:     { type: String, required: true },
  status:   { type: String, enum: ["pending", "verified", "rejected"], default: "pending" },
  fileUrl:  { type: String },
  uploadedAt:{ type: Date, default: Date.now },
});
const Document = mongoose.model("Document", documentSchema);

// NOTIFICATION MODEL
const notificationSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  isGlobal: { type: Boolean, default: false },
  type:     { type: String, enum: ["urgent", "reminder", "info", "success"], default: "info" },
  title:    { type: String, required: true },
  message:  { type: String, required: true },
  read:     { type: Boolean, default: false },
  createdAt:{ type: Date, default: Date.now },
});
const Notification = mongoose.model("Notification", notificationSchema);

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
const protect = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Not authorized" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin access only" });
  next();
};

// ============================================================
// DEFAULT CHECKLIST ITEMS (created when a student registers)
// ============================================================
const DEFAULT_CHECKLIST = [
  { title: "Upload 10th Marksheet",              category: "Documents",     priority: "high",   due: "Week 1",  status: "pending" },
  { title: "Upload 12th / Diploma Marksheet",    category: "Documents",     priority: "high",   due: "Week 1",  status: "pending" },
  { title: "Submit Aadhar Card Copy",            category: "Documents",     priority: "medium", due: "Week 1",  status: "pending" },
  { title: "Submit Caste Certificate",           category: "Documents",     priority: "medium", due: "Week 2",  status: "pending" },
  { title: "Pay Semester 1 Tuition Fee",         category: "Fees",          priority: "high",   due: "Week 1",  status: "pending" },
  { title: "Pay Library & Lab Fee",              category: "Fees",          priority: "medium", due: "Week 2",  status: "pending" },
  { title: "Complete Course Registration",       category: "Registration",  priority: "high",   due: "Week 1",  status: "pending" },
  { title: "Set up College Email ID",            category: "Registration",  priority: "high",   due: "Week 1",  status: "pending" },
  { title: "Activate LMS (Moodle) Account",      category: "Registration",  priority: "high",   due: "Week 2",  status: "pending" },
  { title: "Submit Hostel Application",          category: "Hostel & Campus", priority: "low",  due: "Week 3",  status: "pending" },
  { title: "Collect ID Card",                    category: "Hostel & Campus", priority: "medium",due: "Week 3",  status: "pending" },
  { title: "Download Timetable from Portal",     category: "Academics",     priority: "medium", due: "Week 4",  status: "locked"  },
  { title: "Register for NPTEL Courses",         category: "Academics",     priority: "low",    due: "Week 5",  status: "locked"  },
];

// ============================================================
// ROUTES — AUTH
// ============================================================

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role, branch, year, phone } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ message: "Name, email and password are required" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: "Email already registered" });

    const hashed = await bcrypt.hash(password, 10);
    const studentId = role === "student"
      ? "TCET" + new Date().getFullYear() + Math.floor(100 + Math.random() * 900)
      : null;

    const user = await User.create({ name, email, password: hashed, role: role || "student", studentId, branch, year, phone });

    // Create default checklist for new students
    if (user.role === "student") {
      const items = DEFAULT_CHECKLIST.map(item => ({ ...item, userId: user._id }));
      await Checklist.insertMany(items);

      // Welcome notification
      await Notification.create({
        userId: user._id,
        type: "success",
        title: "Welcome to TCET! 🎉",
        message: `Hi ${name}! Your onboarding portal is ready. Complete your checklist to get started.`,
      });
    }

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.status(201).json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role, studentId: user.studentId, branch: user.branch, year: user.year },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid email or password" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid email or password" });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role, studentId: user.studentId, branch: user.branch, year: user.year },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET CURRENT USER
app.get("/api/auth/me", protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ============================================================
// ROUTES — CHECKLIST
// ============================================================

// GET all checklist items for logged-in student
app.get("/api/checklist", protect, async (req, res) => {
  try {
    const items = await Checklist.find({ userId: req.user.id }).sort({ category: 1 });
    res.json(items);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// UPDATE a checklist item (toggle done/pending)
app.patch("/api/checklist/:id", protect, async (req, res) => {
  try {
    const item = await Checklist.findOne({ _id: req.params.id, userId: req.user.id });
    if (!item) return res.status(404).json({ message: "Item not found" });
    if (item.status === "locked") return res.status(400).json({ message: "This task is locked" });

    item.status = req.body.status;
    item.updatedAt = new Date();
    await item.save();
    res.json(item);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET progress percentage
app.get("/api/checklist/progress", protect, async (req, res) => {
  try {
    const all = await Checklist.find({ userId: req.user.id });
    const done = all.filter(i => i.status === "done").length;
    const progress = all.length ? Math.round((done / all.length) * 100) : 0;
    res.json({ progress, done, total: all.length });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ============================================================
// ROUTES — DOCUMENTS
// ============================================================

// GET all documents for logged-in student
app.get("/api/documents", protect, async (req, res) => {
  try {
    const docs = await Document.find({ userId: req.user.id }).sort({ uploadedAt: -1 });
    res.json(docs);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ADD a document
app.post("/api/documents/upload", protect, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No file uploaded" });

    const doc = await Document.create({
      userId: req.user.id,
      name: req.body.name || req.file.originalname,
      fileUrl: req.file.path,
      status: "pending",
    });

    res.status(201).json(doc);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ADMIN: verify or reject a document
// ADMIN: verify or reject a document
app.patch("/api/documents/:id/status", protect, adminOnly, async (req, res) => {
  try {
    const doc = await Document.findByIdAndUpdate(
      req.params.id,
      { status: req.body.status },
      { new: true }
    );
    if (!doc) return res.status(404).json({ message: "Document not found" });

    // Notify student
    await Notification.create({
      userId: doc.userId,
      type: req.body.status === "verified" ? "success" : "urgent",
      title: req.body.status === "verified" ? "Document Verified ✓" : "Document Rejected ✗",
      message: `Your document "${doc.name}" has been ${req.body.status}.`,
    });

    // Email the student
    const student = await User.findById(doc.userId).select("name email");
    if (student) {
      await sendEmail(
        student.email,
        req.body.status === "verified" ? "✅ Document Verified — TCET Onboarding" : "❌ Document Rejected — TCET Onboarding",
        broadcastTemplate(
          req.body.status === "verified" ? `Document Verified ✓` : `Document Rejected ✗`,
          req.body.status === "verified"
            ? `Your document "${doc.name}" has been successfully verified by the admin. You can continue with your onboarding checklist.`
            : `Your document "${doc.name}" was rejected. Please re-upload a clearer copy and make sure it's the correct document.`
        )
      );
    }

    res.json(doc);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ADMIN: get all documents from all students
app.get("/api/admin/documents", protect, adminOnly, async (req, res) => {
  try {
    const docs = await Document.find()
      .populate("userId", "name email studentId")
      .sort({ uploadedAt: -1 });
    res.json(docs);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// ============================================================
// ROUTES — NOTIFICATIONS
// ============================================================

// GET notifications for logged-in user
app.get("/api/notifications", protect, async (req, res) => {
  try {
    const notes = await Notification.find({
      $or: [{ userId: req.user.id }, { isGlobal: true }],
    }).sort({ createdAt: -1 }).limit(20);
    res.json(notes);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// MARK notification as read
app.patch("/api/notifications/:id/read", protect, async (req, res) => {
  try {
    const note = await Notification.findByIdAndUpdate(req.params.id, { read: true }, { new: true });
    res.json(note);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ADMIN: broadcast notification to all students
app.post("/api/notifications/broadcast", protect, adminOnly, async (req, res) => {
  try {
    const { title, message, type } = req.body;
    const note = await Notification.create({ isGlobal: true, title, message, type: type || "info" });
    res.status(201).json(note);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ============================================================
// ROUTES — ADMIN
// ============================================================

// GET all students with their progress
app.get("/api/admin/students", protect, adminOnly, async (req, res) => {
  try {
    const students = await User.find({ role: "student" }).select("-password");

    const studentsWithProgress = await Promise.all(students.map(async (s) => {
      const all = await Checklist.find({ userId: s._id });
      const done = all.filter(i => i.status === "done").length;
      const progress = all.length ? Math.round((done / all.length) * 100) : 0;
      return { ...s.toObject(), progress, tasksTotal: all.length, tasksDone: done };
    }));

    res.json(studentsWithProgress);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET admin stats summary
app.get("/api/admin/stats", protect, adminOnly, async (req, res) => {
  try {
    const total = await User.countDocuments({ role: "student" });
    const allChecklists = await Checklist.find();

    // Group by userId
    const progressMap = {};
    allChecklists.forEach(item => {
      const uid = item.userId.toString();
      if (!progressMap[uid]) progressMap[uid] = { done: 0, total: 0 };
      progressMap[uid].total++;
      if (item.status === "done") progressMap[uid].done++;
    });

    let complete = 0, inProgress = 0, atRisk = 0;
    Object.values(progressMap).forEach(({ done, total }) => {
      const pct = total ? (done / total) * 100 : 0;
      if (pct === 100) complete++;
      else if (pct < 40) atRisk++;
      else inProgress++;
    });

    res.json({ total, complete, inProgress, atRisk });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});



// ============================================================
// EMAIL SETUP
// ============================================================

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Helper function to send email
const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({
      from: `"TCET Onboarding" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
    });
    console.log(`✅ Email sent to ${to}`);
    return true;
  } catch (err) {
    console.log(`❌ Email failed to ${to}:`, err.message);
    return false;
  }
};

// Email templates
const deadlineReminderTemplate = (studentName, tasks) => `
  <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0a0f2e; color: #f8fafc; padding: 32px; border-radius: 16px;">
    <div style="text-align: center; margin-bottom: 32px;">
      <h1 style="color: #3b82f6; font-size: 28px; margin-bottom: 8px;">🎓 TCET Onboarding</h1>
      <p style="color: #64748b;">Smart Student Onboarding Portal</p>
    </div>

    <h2 style="font-size: 20px; margin-bottom: 8px;">Hi ${studentName}! 👋</h2>
    <p style="color: #94a3b8; margin-bottom: 24px;">
      You have <strong style="color: #f59e0b;">${tasks.length} pending task(s)</strong> that need your attention soon.
    </p>

    <div style="background: rgba(37,99,235,0.1); border: 1px solid rgba(37,99,235,0.3); border-radius: 12px; padding: 20px; margin-bottom: 24px;">
      <h3 style="color: #3b82f6; margin-bottom: 16px;">⏳ Pending Tasks:</h3>
      ${tasks.map(t => `
        <div style="display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
          <span style="color: #f1f5f9;">📋 ${t.title}</span>
          <span style="color: #f59e0b; font-weight: bold;">Due: ${t.due}</span>
        </div>
      `).join("")}
    </div>

    <div style="text-align: center; margin-bottom: 24px;">
      <a href="http://localhost:3000" 
        style="background: linear-gradient(135deg, #2563eb, #06b6d4); color: white; padding: 14px 32px; border-radius: 10px; text-decoration: none; font-weight: bold; font-size: 15px;">
        Complete Tasks Now →
      </a>
    </div>

    <p style="color: #475569; font-size: 13px; text-align: center;">
      This is an automated reminder from TCET Smart Onboarding System.<br/>
      Powered by TCS · TCET ACM · SIGAI
    </p>
  </div>
`;

const broadcastTemplate = (title, message) => `
  <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0a0f2e; color: #f8fafc; padding: 32px; border-radius: 16px;">
    <div style="text-align: center; margin-bottom: 32px;">
      <h1 style="color: #3b82f6; font-size: 28px; margin-bottom: 8px;">🎓 TCET Onboarding</h1>
      <p style="color: #64748b;">Smart Student Onboarding Portal</p>
    </div>

    <div style="background: rgba(37,99,235,0.1); border: 1px solid rgba(37,99,235,0.3); border-radius: 12px; padding: 24px; margin-bottom: 24px;">
      <h2 style="color: #f1f5f9; margin-bottom: 12px;">📢 ${title}</h2>
      <p style="color: #94a3b8; line-height: 1.6;">${message}</p>
    </div>

    <div style="text-align: center; margin-bottom: 24px;">
      <a href="http://localhost:3000"
        style="background: linear-gradient(135deg, #2563eb, #06b6d4); color: white; padding: 14px 32px; border-radius: 10px; text-decoration: none; font-weight: bold; font-size: 15px;">
        Open Onboarding Portal →
      </a>
    </div>

    <p style="color: #475569; font-size: 13px; text-align: center;">
      This message was sent by TCET Admin.<br/>
      Powered by TCS · TCET ACM · SIGAI
    </p>
  </div>
`;

// ============================================================
// EMAIL ROUTES
// ============================================================

// ADMIN: Send broadcast email to all students
app.post("/api/email/broadcast", protect, adminOnly, async (req, res) => {
  try {
    const { title, message } = req.body;
    if (!title || !message)
      return res.status(400).json({ message: "Title and message required" });

    // Get all students
    const students = await User.find({ role: "student" }).select("name email");
    if (students.length === 0)
      return res.status(404).json({ message: "No students found" });

    // Send email to all students
    let sent = 0;
    for (const student of students) {
      const success = await sendEmail(
        student.email,
        `📢 ${title} — TCET Onboarding`,
        broadcastTemplate(title, message)
      );
      if (success) sent++;
    }

    // Also save as notification in DB
    await Notification.create({
      isGlobal: true,
      type: "info",
      title,
      message,
    });

    res.json({ message: `Email sent to ${sent}/${students.length} students` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Send reminder email to a specific student
app.post("/api/email/remind/:userId", protect, adminOnly, async (req, res) => {
  try {
    const student = await User.findById(req.params.userId).select("name email");
    if (!student) return res.status(404).json({ message: "Student not found" });

    const pendingTasks = await Checklist.find({
      userId: req.params.userId,
      status: "pending",
    });

    if (pendingTasks.length === 0)
      return res.json({ message: "Student has no pending tasks" });

    await sendEmail(
      student.email,
      "⏳ Pending Tasks Reminder — TCET Onboarding",
      deadlineReminderTemplate(student.name, pendingTasks)
    );

    res.json({ message: `Reminder sent to ${student.email}` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Test email route (for testing only)
app.post("/api/email/test", protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("name email");
    await sendEmail(
      user.email,
      "✅ Test Email — TCET Onboarding",
      broadcastTemplate("Test Email Working!", "Your email notifications are set up correctly. You will now receive reminders and updates from TCET Onboarding Portal.")
    );
    res.json({ message: `Test email sent to ${user.email}` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ============================================================
// AUTO DEADLINE REMINDERS (runs every day at 8:00 AM)
// ============================================================
cron.schedule("0 8 * * *", async () => {
  console.log("⏰ Running daily deadline reminder job...");
  try {
    const students = await User.find({ role: "student" }).select("name email");

    for (const student of students) {
      const pendingTasks = await Checklist.find({
        userId: student._id,
        status: "pending",
        priority: "high",
      });

      if (pendingTasks.length > 0) {
        await sendEmail(
          student.email,
          "⏳ You have pending onboarding tasks!",
          deadlineReminderTemplate(student.name, pendingTasks)
        );
      }
    }
    console.log("✅ Deadline reminders sent!");
  } catch (err) {
    console.log("❌ Cron job error:", err.message);
  }
});
// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));