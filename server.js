const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const path = require("path");
const ExcelJS = require("exceljs");

const app = express();
const pool = require("./db");

/* ================= DATABASE CHECK ================= */
pool.query("SELECT current_database(), inet_server_addr()")
    .then(res => console.log("Connected to DB:", res.rows[0]))
    .catch(err => console.error("DB error:", err));

/* ================= MIDDLEWARE ================= */
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(cookieParser("super-secret-key"));   // COOKIE SIGNING KEY

app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data: https://ui-avatars.com; " +
        "connect-src 'self' https://cdn.jsdelivr.net;"
    );
    next();
});

/* ================= AUTH MIDDLEWARE ================= */
const isAuth = (req, res, next) => {
    if (req.signedCookies.user) {
        req.user = req.signedCookies.user;
        next();
    } else {
        res.redirect("/login");
    }
};

/* ================= ROUTES ================= */

app.get("/", (req, res) => res.redirect("/login"));
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));

/* ================= REGISTER ================= */
app.post("/register", async (req, res) => {
    try {
        const { name, email, password, role, dept, designation, year } = req.body;
        const hashedPw = await bcrypt.hash(password, 10);

        await pool.query(
            "INSERT INTO users (full_name, email, password, role, department, designation, roll_number) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            [name, email, hashedPw, role, dept, designation || null, year || null]
        );

        res.redirect("/login");
    } catch (err) {
        console.error(err);
        res.send("Registration error");
    }
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

    if (user.rows.length > 0 && await bcrypt.compare(password, user.rows[0].password)) {

        res.cookie("user", {
            id: user.rows[0].id,
            role: user.rows[0].role
        }, {
            signed: true,
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 1000 * 60 * 60 * 24 * 30   // 30 days
        });

        res.redirect(user.rows[0].role === "teacher" ? "/teacher-dash" : "/student-dash");

    } else {
        res.send("Invalid Credentials");
    }
});

/* ================= LOGOUT ================= */
app.get("/logout", (req, res) => {
    res.clearCookie("user");
    res.redirect("/login");
});

/* ================= PROFILE ================= */
app.get("/profile", isAuth, async (req, res) => {
    const user = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
    res.render("profile", { user: user.rows[0] });
});

/* ================= TEACHER DASHBOARD ================= */
app.get("/teacher-dash", isAuth, async (req, res) => {
    const internships = await pool.query(
        `SELECT i.*, COUNT(a.id) as applicant_count 
         FROM internships i
         LEFT JOIN applications a ON i.id = a.internship_id
         WHERE i.posted_by_id = $1
         GROUP BY i.id
         ORDER BY i.created_at DESC`,
        [req.user.id]
    );
    res.render("teacher-dash", { internships: internships.rows });
});

/* ================= STUDENT DASHBOARD ================= */
app.get("/student-dash", isAuth, async (req, res) => {
    const internships = await pool.query(`
        SELECT i.*, u.full_name as recruiter
        FROM internships i
        JOIN users u ON i.posted_by_id = u.id
    `);
    res.render("student-dash", { internships: internships.rows });
});

/* ================= APPLY ================= */
app.post("/apply/:id", isAuth, async (req, res) => {
    await pool.query(
        "INSERT INTO applications (student_id, internship_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
        [req.user.id, req.params.id]
    );
    res.redirect("/my-applications");
});

/* ================= MY APPLICATIONS ================= */
app.get("/my-applications", isAuth, async (req, res) => {
    const apps = await pool.query(
        `SELECT a.*, i.title, i.link 
         FROM applications a
         JOIN internships i ON a.internship_id = i.id
         WHERE a.student_id = $1`,
        [req.user.id]
    );
    res.render("my-apps", { apps: apps.rows });
});

/* ================= UPDATE STATUS ================= */
app.post("/update-app-status/:id", isAuth, async (req, res) => {
    await pool.query(
        "UPDATE applications SET status=$1 WHERE id=$2 AND student_id=$3",
        [req.body.status, req.params.id, req.user.id]
    );
    res.redirect("/my-applications");
});

/* ================= REMOVE APPLICATION ================= */
app.post("/remove-application/:id", isAuth, async (req, res) => {
    await pool.query(
        "DELETE FROM applications WHERE id=$1 AND student_id=$2",
        [req.params.id, req.user.id]
    );
    res.redirect("/my-applications");
});

/* ================= START SERVER ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port", PORT));
