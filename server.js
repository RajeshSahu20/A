require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const multer = require("multer");

const db = require("./database");
const {
    requireLogin,
    requireAdmin,
    hashPassword,
    verifyPassword
} = require("./auth");

const app = express();
const PORT = 3000;

if (!process.env.SESSION_SECRET ||
    !process.env.ADMIN_USERNAME ||
    !process.env.ADMIN_PASSWORD) {
    throw new Error("Please configure SESSION_SECRET and admin credentials in .env");
}

const uploadsFolder = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadsFolder)) {
    fs.mkdirSync(uploadsFolder, { recursive: true });
}

const allowedPhotoTypes = new Set([
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/bmp"
]);

const storage = multer.diskStorage({
    destination: (req, file, callback) => {
        callback(null, uploadsFolder);
    },
    filename: (req, file, callback) => {
        const extension = path.extname(file.originalname).toLowerCase();
        callback(null, `${Date.now()}-${require("crypto").randomUUID()}${extension}`);
    }
});

const uploadPhoto = multer({
    storage,
    limits: {
        fileSize: 10 * 1024 * 1024
    },
    fileFilter: (req, file, callback) => {
        if (!allowedPhotoTypes.has(file.mimetype)) {
            return callback(new Error("Only JPG, PNG, GIF, WEBP and BMP photos are allowed."));
        }

        callback(null, true);
    }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    name: "photovault.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: 30 * 60 * 1000
    }
}));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});
//app.use("/uploads", express.static(uploadsFolder));

app.get("/gallery", requireLogin, (req, res) => {
    try {
        const files = fs.readdirSync(uploadsFolder);

        const photos = files.filter(file =>
            /\.(jpg|jpeg|png|gif|webp|bmp)$/i.test(file)
        );

        res.json({
            success: true,
            photos
        });
    } catch (error) {
        console.error("Gallery error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to load photos."
        });
    }
});
app.get("/api/photos/:filename", requireLogin, (req, res) => {
    try {
        const filename = req.params.filename;

        if (path.basename(filename) !== filename) {
            return res.status(400).json({
                success: false,
                message: "Invalid filename."
            });
        }

        if (!/\.(jpg|jpeg|png|gif|webp|bmp)$/i.test(filename)) {
            return res.status(400).json({
                success: false,
                message: "Invalid photo type."
            });
        }

        const filePath = path.join(uploadsFolder, filename);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({
                success: false,
                message: "Photo not found."
            });
        }

        res.sendFile(filePath);
    } catch (error) {
        console.error("Photo loading error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to load photo."
        });
    }
});

async function createDefaultAdmin() {
    const username = process.env.ADMIN_USERNAME.trim();
    const password = process.env.ADMIN_PASSWORD;

    const existingAdmin = db.prepare(
        "SELECT id FROM admins WHERE username = ?"
    ).get(username);

    if (!existingAdmin) {
        const passwordHash = await hashPassword(password);

        db.prepare(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)"
        ).run(username, passwordHash);

        console.log("Default admin account created.");
    }
}

app.post("/api/login", async (req, res) => {
    try {
        const email = String(req.body.email || "").trim();
        const pin = String(req.body.pin || "");

        if (!email || !/^\d{4}$/.test(pin)) {
            return res.status(400).json({
                success: false,
                message: "Enter your registered Gmail and 4-digit PIN."
            });
        }

        const student = db.prepare(
            "SELECT id, name, email, pin_hash, status FROM students WHERE email = ?"
        ).get(email);

        if (
            !student ||
            student.status !== "active" ||
            !(await verifyPassword(pin, student.pin_hash))
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid Gmail or PIN."
            });
        }

        req.session.regenerate((err) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Unable to start your session."
                });
            }

            req.session.studentId = student.id;
            req.session.studentName = student.name;

            req.session.save((saveError) => {
                if (saveError) {
                    return res.status(500).json({
                        success: false,
                        message: "Unable to save your login session."
                    });
                }

                res.json({
                    success: true,
                    message: "Login successful!",
                    student: {
                        name: student.name,
                        email: student.email
                    }
                });
            });
        });
    } catch (error) {
        console.error("Student login error:", error);

        res.status(500).json({
            success: false,
            message: "Something went wrong during login."
        });
    }
});
app.post("/upload", requireLogin, (req, res, next) => {
    uploadPhoto.single("photo")(req, res, (err) => {
        if (err) {
            return res.status(400).json({
                success: false,
                message: err.message || "Photo upload failed."
            });
        }

        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: "Please select a photo."
            });
        }

        res.status(201).json({
            success: true,
            message: "Photo uploaded successfully!",
            filename: req.file.filename
        });
    });
});
app.get("/api/me", (req, res) => {
    if (!req.session.studentId) {
        return res.json({
            loggedIn: false
        });
    }

    res.json({
        loggedIn: true,
        student: {
            id: req.session.studentId,
            name: req.session.studentName
        }
    });
});

app.post("/api/logout", requireLogin, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({
                success: false,
                message: "Logout failed."
            });
        }

        res.clearCookie("photovault.sid");

        res.json({
            success: true,
            message: "Logged out successfully."
        });
    });
});

app.post("/api/admin/login", async (req, res) => {
    try {
        const username = String(req.body.username || "").trim();
        const password = String(req.body.password || "");

        const admin = db.prepare(
            "SELECT id, username, password_hash FROM admins WHERE username = ?"
        ).get(username);

        if (
            !admin ||
            !(await verifyPassword(password, admin.password_hash))
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid admin username or password."
            });
        }

        req.session.regenerate((err) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Unable to start admin session."
                });
            }

            req.session.adminId = admin.id;
            req.session.adminUsername = admin.username;

            req.session.save((saveError) => {
                if (saveError) {
                    return res.status(500).json({
                        success: false,
                        message: "Unable to save admin session."
                    });
                }

                res.json({
                    success: true,
                    message: "Admin login successful!"
                });
            });
        });
    } catch (error) {
        console.error("Admin login error:", error);

        res.status(500).json({
            success: false,
            message: "Something went wrong during admin login."
        });
    }
});

app.get("/api/admin/me", (req, res) => {
    res.json({
        loggedIn: Boolean(req.session.adminId),
        username: req.session.adminUsername || null
    });
});

app.post("/api/admin/logout", requireAdmin, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({
                success: false,
                message: "Admin logout failed."
            });
        }

        res.clearCookie("photovault.sid");

        res.json({
            success: true,
            message: "Admin logged out successfully."
        });
    });
});

app.get("/api/student-area", requireLogin, (req, res) => {
    res.json({
        success: true,
        message: "Student area accessed successfully."
    });
});

app.get("/api/admin-area", requireAdmin, (req, res) => {
    res.json({
        success: true,
        message: "Admin area accessed successfully."
    });
});

// Get all student accounts
app.get("/api/admin/students", requireAdmin, (req, res) => {
    try {
        const students = db.prepare(
            "SELECT id, name, email, status, created_at FROM students ORDER BY id DESC"
        ).all();

        res.json({
            success: true,
            students
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            success: false,
            message: "Unable to load student accounts."
        });
    }
});

// Add a student account
app.post("/api/admin/students", requireAdmin, async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const email = String(req.body.email || "").trim();
        const pin = String(req.body.pin || "");

        if (!name || name.length > 100) {
            return res.status(400).json({
                success: false,
                message: "Enter a valid student name."
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
            return res.status(400).json({
                success: false,
                message: "Enter a valid Gmail or email address."
            });
        }

        if (!/^\d{4}$/.test(pin)) {
            return res.status(400).json({
                success: false,
                message: "PIN must contain exactly 4 digits."
            });
        }

        const existingStudent = db.prepare(
            "SELECT id FROM students WHERE email = ?"
        ).get(email);

        if (existingStudent) {
            return res.status(409).json({
                success: false,
                message: "An account with this email already exists."
            });
        }

        const pinHash = await hashPassword(pin);

        const result = db.prepare(
            "INSERT INTO students (name, email, pin_hash) VALUES (?, ?, ?)"
        ).run(name, email, pinHash);

        res.status(201).json({
            success: true,
            message: "Student account created successfully.",
            student: {
                id: result.lastInsertRowid,
                name,
                email
            }
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            success: false,
            message: "Unable to create student account."
        });
    }
});

// Activate or deactivate a student account
app.patch("/api/admin/students/:id/status", requireAdmin, (req, res) => {
    try {
        const id = Number(req.params.id);
        const status = req.body.status;

        if (!Number.isSafeInteger(id) || id < 1 ||
            !["active", "inactive"].includes(status)) {
            return res.status(400).json({
                success: false,
                message: "Invalid student ID or account status."
            });
        }

        const result = db.prepare(
            "UPDATE students SET status = ? WHERE id = ?"
        ).run(status, id);

        if (result.changes === 0) {
            return res.status(404).json({
                success: false,
                message: "Student account not found."
            });
        }

        res.json({
            success: true,
            message: "Student account status updated."
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            success: false,
            message: "Unable to update account status."
        });
    }
});

// Delete a student account
app.delete("/api/admin/students/:id", requireAdmin, (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isSafeInteger(id) || id < 1) {
            return res.status(400).json({
                success: false,
                message: "Invalid student ID."
            });
        }

        const result = db.prepare(
            "DELETE FROM students WHERE id = ?"
        ).run(id);

        if (result.changes === 0) {
            return res.status(404).json({
                success: false,
                message: "Student account not found."
            });
        }

        res.json({
            success: true,
            message: "Student account deleted."
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            success: false,
            message: "Unable to delete student account."
        });
    }
});

async function startServer() {
    await createDefaultAdmin();

    app.listen(PORT, () => {
        console.log(`PhotoVault running at http://localhost:${PORT}`);
    });
}

startServer().catch((error) => {
    console.error("Unable to start PhotoVault:", error);
    process.exit(1);
});