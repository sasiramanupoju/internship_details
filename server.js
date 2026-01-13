const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const helmet = require('helmet'); // Recommended for security

const app = express();
// const pool = new Pool({
//     user: 'postgres', // Change to your DB username
//     host: 'localhost',
//     database: 'internship_db', // Change to your DB name
//     password: 'Sasi@191199', // Change to your DB password
//     port: 5432,
// });

const pool = require("./db");

pool.query("SELECT current_database(), inet_server_addr()")
  .then(res => {
    console.log("Connected to DB:", res.rows[0]);
  })
  .catch(err => console.error("DB error:", err));


app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
// app.use(express.static('public'));

// Replace line 32 in your server.js 
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true
}));

// app.use((req, res, next) => {
//     res.setHeader(
//         "Content-Security-Policy",
//         "default-src 'self'; " +
//         // Added 'unsafe-inline' to the line below
//         "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " + 
//         "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; " +
//         "font-src 'self' https://fonts.gstatic.com; " +
//         "img-src 'self' data: https://ui-avatars.com; " +
//         "connect-src 'self' ws://localhost:* http://localhost:*;"
//     );
//     next();
// });

app.use(
    helmet.contentSecurityPolicy({
        directives: {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
            "img-src": ["'self'", "data:", "https://ui-avatars.com"],
            "connect-src": ["'self'", "https://cdn.jsdelivr.net"]
        },
    })
); 

// Middleware to check auth
const isAuth = (req, res, next) => {
    if (req.session.userId) next();
    else res.redirect('/login');
};

// --- ROUTES ---

app.get('/', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

app.get('/applicants/:id', isAuth, async (req, res) => {
    const internshipId = req.params.id;
    try {
        const students = await pool.query(`
            SELECT u.full_name, u.email, u.department, u.roll_number, a.status, a.applied_at
            FROM applications a
            JOIN users u ON a.student_id = u.id
            WHERE a.internship_id = $1`, [internshipId]);

        const stats = await pool.query(`
            SELECT u.department, COUNT(*) as count
            FROM applications a
            JOIN users u ON a.student_id = u.id
            WHERE a.internship_id = $1
            GROUP BY u.department`, [internshipId]);

        res.render('applicants', { 
            students: students.rows, 
            stats: JSON.stringify(stats.rows), 
            internshipId 
        });
    } catch (err) {
        console.error(err);
        res.send("Error loading applicants");
    }
});

app.get('/profile', isAuth, async (req, res) => {
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
    res.render('profile', { user: user.rows[0] });
});

app.post('/update-profile', isAuth, async (req, res) => {
    const { name, dept, designation, year } = req.body;
    const dbYear = (year && year.trim() !== "") ? year : null;
    
    await pool.query(
        'UPDATE users SET full_name = $1, department = $2, designation = $3, roll_number = $4 WHERE id = $5',
        [name, dept, designation, dbYear, req.session.userId]
    );
    res.redirect('/profile?success=true');
});

app.post('/update-app-status/:id', isAuth, async (req, res) => {
    try {
        const applicationId = req.params.id;
        const newStatus = req.body.status;
        const studentId = req.session.userId;

        // Update the status in the applications table
        await pool.query(
            'UPDATE applications SET status = $1 WHERE id = $2 AND student_id = $3',
            [newStatus, applicationId, studentId]
        );

        res.redirect('/my-applications');
    } catch (err) {
        console.error(err);
        res.status(500).send("Error updating status");
    }
});

// Route to allow students to remove their application status
app.post('/remove-application/:id', isAuth, async (req, res) => {
    try {
        const applicationId = req.params.id;
        const studentId = req.session.userId;

        // Delete the record only if it belongs to the logged-in student
        const result = await pool.query(
            'DELETE FROM applications WHERE id = $1 AND student_id = $2',
            [applicationId, studentId]
        );

        if (result.rowCount > 0) {
            console.log(`Student ${studentId} removed application ${applicationId}`);
        }

        res.redirect('/my-applications');
    } catch (err) {
        console.error("Error removing application:", err);
        res.status(500).send("Internal Server Error");
    }
});

app.post('/register', async (req, res) => {
    try {
        const { name, email, password, role, dept, designation, year } = req.body;
        const hashedPw = await bcrypt.hash(password, 10);

        // FIX: Convert empty strings to null so PostgreSQL doesn't complain
        const dbDesignation = designation || null;
        const dbYear = (year && year.trim() !== "") ? year.trim() : null;

        await pool.query(
            'INSERT INTO users (full_name, email, password, role, department, designation, roll_number) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [name, email, hashedPw, role, dept, dbDesignation, dbYear]
        );
        
        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.status(500).send("Registration Error: " + err.message);
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length > 0 && await bcrypt.compare(password, user.rows[0].password)) {
        req.session.userId = user.rows[0].id;
        req.session.role = user.rows[0].role;
        res.redirect(user.rows[0].role === 'teacher' ? '/teacher-dash' : '/student-dash');
    } else {
        res.send('Invalid Credentials');
    }
});

// Teacher Dashboard
app.get('/teacher-dash', isAuth, async (req, res) => {
    try {
        console.log("Current Teacher ID:", req.session.userId); // Debug Log

        const internships = await pool.query(
            `SELECT i.*, COUNT(a.id) as applicant_count 
             FROM internships i 
             LEFT JOIN applications a ON i.id = a.internship_id 
             WHERE i.posted_by_id = $1 
             GROUP BY i.id 
             ORDER BY i.created_at DESC`, 
            [req.session.userId]
        );
        
        console.log("Found Listings:", internships.rows.length); // Debug Log
        res.render('teacher-dash', { internships: internships.rows });
    } catch (err) {
        console.error("Dashboard Error:", err);
        res.status(500).send("Database Error");
    }
});

// Student Dashboard
app.get('/student-dash', isAuth, async (req, res) => {
    const internships = await pool.query(`
        SELECT i.*, u.full_name as recruiter,
        (SELECT COUNT(*) FROM applications WHERE internship_id = i.id) as applied_count
        FROM internships i JOIN users u ON i.posted_by_id = u.id`);
    res.render('student-dash', { internships: internships.rows });
});

app.post('/post-internship', isAuth, async (req, res) => {
    const { title, link, skills, year, pay, positions } = req.body;
    await pool.query(
        'INSERT INTO internships (title, link, skills_needed, target_year, pay, open_positions, posted_by_id) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [title, link, skills, year, pay, positions, req.session.userId]
    );
    res.redirect('/teacher-dash');
});

app.post('/apply/:id', isAuth, async (req, res) => {
    await pool.query('INSERT INTO applications (student_id, internship_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.session.userId, req.params.id]);
    res.redirect('/my-applications');
});

app.get('/my-applications', isAuth, async (req, res) => {
    const apps = await pool.query(`
        SELECT a.*, i.title, i.link FROM applications a 
        JOIN internships i ON a.internship_id = i.id 
        WHERE a.student_id = $1`, [req.session.userId]);
    res.render('my-apps', { apps: apps.rows });
});

// Place this near your other POST routes in server.js
app.post('/delete-internship/:id', isAuth, async (req, res) => {
    try {
        const internshipId = req.params.id;
        const teacherId = req.session.userId;

        // 1. Delete associated applications first (due to database constraints)
        await pool.query('DELETE FROM applications WHERE internship_id = $1', [internshipId]);

        // 2. Delete the internship only if it belongs to the logged-in teacher
        const result = await pool.query(
            'DELETE FROM internships WHERE id = $1 AND posted_by_id = $2',
            [internshipId, teacherId]
        );

        console.log(`Action: Internship ${internshipId} deleted by Teacher ${teacherId}`);
        res.redirect('/teacher-dash');
    } catch (err) {
        console.error("Delete Error:", err);
        res.status(500).send("Error deleting internship: " + err.message);
    }
});

const ExcelJS = require("exceljs");

app.get("/download-applicants/:internshipId", isAuth, async (req, res) => {
    try {
        const internshipId = req.params.internshipId;

        const result = await pool.query(`
            SELECT 
                i.title AS internship,
                u.full_name,
                u.email,
                u.department,
                u.roll_number,
                a.status,
                TO_CHAR(a.applied_at, 'DD Mon YYYY HH24:MI') AS applied_at
            FROM applications a
            JOIN users u ON a.student_id = u.id
            JOIN internships i ON a.internship_id = i.id
            WHERE a.internship_id = $1
            ORDER BY u.full_name
        `, [internshipId]);

        const workbook = new ExcelJS.Workbook();
        const sheet = workbook.addWorksheet("Applicants");

        sheet.columns = [
            { header: "Internship", key: "internship", width: 30 },
            { header: "Student Name", key: "full_name", width: 25 },
            { header: "Email", key: "email", width: 30 },
            { header: "Department", key: "department", width: 20 },
            { header: "Year of Study", key: "roll_number", width: 15 },
            { header: "Status", key: "status", width: 15 },
            { header: "Applied At", key: "applied_at", width: 22 }
        ];

        result.rows.forEach(row => {
            sheet.addRow(row);
        });

        res.setHeader(
            "Content-Type",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        );
        res.setHeader(
            "Content-Disposition",
            "attachment; filename=Internship_Applicants.xlsx"
        );

        await workbook.xlsx.write(res);
        res.end();
    } catch (err) {
        console.error("Excel Export Error:", err);
        res.status(500).send("Failed to generate Excel file");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});


// app.listen(3000, () => console.log('Server running on http://localhost:3000'));
