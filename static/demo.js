//Excel file send
/*
app.get('/assets/downloadAssets', async (req, res) => {
    try {
        const [results] = await pool.execute('SELECT * FROM Assets');
        if (!results || results.length === 0) {
            return res.status(404).send('No Assets found in the database');
        }

        // Prepare data for Excel
        const data = [["Location", "Sub Location", "Status", "Employee ID",
            "Username", "Asset Type", "Asset Make",
            "Asset Serial Number", "Asset Model", "Invoice Number",
            "PO Number", "AMC Invoice Number", "Warranty Status",
            "Warranty Start Date", "Warranty End Date",
            "Warranty Tenure", "Date of Purchase", "Year of Purchase",
            "Price of Asset", "Vendor Name",
            "Vendor Contact Number", "Vendor Mail ID", "Processor",
            "CPU Speed", "RAM Installed", "HDD/SSD Capacity",
            "Operating System", "OS License"]];

        results.forEach(row => {
            data.push([row["location"], row["subLocation"], row["status"],
                row["employeeId"], row["username"], row["assetType"], row["assetMake"],
                row["assetSerialNumber"], row["assetModel"], row["invoiceNumber"], row["poNumber"],
                row["amcInvoiceNumber"], row["warrantyStatus"], row["warrantyStartDate"],
                row["warrantyEndDate"], row["warrantyTenure"], row["purchaseDate"],
                row["purchaseYear"], row["price"], row["vendorName"], row["contactNumber"],
                row["mailId"], row["processor"], row["cpuSpeed"],
                row["ramInstalled"], row["hddCapacity"], row["operatingSystem"],
                row["osLicense"]]);
        });

        // Create Excel file in memory
        const worksheet = xlsx.utils.aoa_to_sheet(data);
        const workbook = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(workbook, worksheet, "Assets");

        // Generate Excel file buffer
        const excelBuffer = xlsx.write(workbook, { bookType: 'xlsx', type: 'buffer' });

        // Set response headers for file download
        res.setHeader('Content-Disposition', 'attachment; filename=assets.xlsx');
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

        // Send the Excel file buffer as response
        res.send(excelBuffer);

        console.log('Excel file sent successfully.');
        notifier.notify({
            title: 'Salutations!',
            message: 'Asset details downloaded',
            icon: path.join(__dirname, 'icon.jpg'),
            sound: true,
            wait: true
        });
    } catch (error) {
        console.error('Error generating Excel file:', error);
        res.status(500).send('Error generating Excel file');
    }
});
*/

//Frontend of excel file download
/*
document.getElementById('downloadAssetsButton').addEventListener('click', async function (event) {
    event.preventDefault();
    try {
        const response = await fetch('/assets/downloadAssets', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
        });

        // Check if the response is ok (status 200-299)
        if (response.ok) {
            const blob = await response.blob(); // Get the response as a Blob
            const url = window.URL.createObjectURL(blob); // Create a URL for the Blob
            const a = document.createElement('a'); // Create a link element
            a.style.display = 'none';
            a.href = url; // Set the link to the Blob URL
            a.download = 'assets.xlsx'; // Set the default file name
            document.body.appendChild(a); // Append link to the body
            a.click(); // Programmatically click the link to trigger the download
            window.URL.revokeObjectURL(url); // Clean up the URL object
            a.remove(); // Remove the link from the document
        } else {
            const data = await response.json();
            alert(data.message || 'Failed to download asset details.');
        }
    } catch (error) {
        console.error('Error downloading assets:', error);
        alert('Error downloading asset details. Please try again later.');
    }
});
*/

import express from 'express';
import mysql from 'mysql2/promise';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import xlsx from 'xlsx';
import notifier from 'node-notifier';
import cors from 'cors';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import https from 'https';
import fs from 'fs';
import bcrypt from 'bcrypt';  // Import bcrypt for password hashing
import helmet from 'helmet';  // Import helmet for security headers

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = process.env.PORT || 3000; // Set a default port
const JWT_SECRET = process.env.JWT_SECRET;

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

// Middleware
app.use(helmet()); // Set security HTTP headers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'static'));
app.use(express.static(path.join(__dirname, 'static')));
app.use(cors());
app.use(cookieParser());
app.setMaxListeners(1000);
app.use(session({
    secret: process.env.APP_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true, maxAge: 30 * 60 * 1000 } // 30 minutes
}));

const activeSessions = new Map();

app.post('/loginUser', async (req, res) => {
    const { employeeId, password } = req.body;
    const query = `SELECT * FROM Users WHERE employeeId = ?`;

    try {
        const [result] = await pool.execute(query, [employeeId]);
        if (result.length > 0) {
            const user = result[0];
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {
                const sessions = activeSessions.get(employeeId) || [];
                if (sessions.length >= 2) {
                    return res.status(403).json({ message: 'Session limit reached' });
                }

                req.session.user = {
                    employeeId: user.employeeId,
                    employeeName: user.employeeName,
                    subLocation: user.subLocation,
                    userType: user.userType,
                    userStatus: user.userStatus
                };

                sessions.push(req.session.id);
                activeSessions.set(employeeId, sessions);

                res.status(200).json({ message: 'Successful login', result });
            } else {
                res.status(401).json({ message: 'Invalid credentials' });
            }
        } else {
            res.status(401).json({ message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error finding user:', error);
        res.status(500).json({ error: 'Failed to find user', details: error.message });
    }
});

// Cleanup expired sessions
app.use((req, res, next) => {
    const now = Date.now();
    activeSessions.forEach((sessions, employeeId) => {
        activeSessions.set(employeeId, sessions.filter(sessionId => sessionId !== req.session.id));
        if (activeSessions.get(employeeId).length === 0) {
            activeSessions.delete(employeeId);
        }
    });
    next();
});

// Set up HTTPS server
const options = {
    key: fs.readFileSync('path/to/your/private-key.pem'), // Update with your path
    cert: fs.readFileSync('path/to/your/certificate.pem') // Update with your path
};

https.createServer(options, app).listen(port, () => {
    console.log(`Server running on https://0.0.0.0:${port}`);
});



