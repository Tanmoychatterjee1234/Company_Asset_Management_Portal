import express from 'express';
import mysql from 'mysql2/promise';
import path from 'path'
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import xlsx from 'xlsx';
import notifier from 'node-notifier';
import cors from 'cors';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import http from 'http';
dotenv.config();


const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = process.env.port;
const JWT_SECRET = process.env.JWT_SECRET;

const pool = mysql.createPool({
    uri: `mysql://${process.env.user}:${process.env.dbpassword}@${process.env.host}:${process.env.dbport}/${process.env.database}`,
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'static'));
app.use(express.static('static'));
app.use(express.static(path.join(__dirname, 'static')));
app.use(cors());
app.use(cookieParser());
app.setMaxListeners(1000);
app.use(session({
    secret: process.env.appsecret,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 30 * 60 * 1000
    }
}));



app.get('/', async (req, res) => {
    res.sendFile(path.join(__dirname, 'static', 'signin.html'));
});

app.get('/signinUser', async (req, res) => {
    res.sendFile(path.join(__dirname, 'static', 'signin.html'));
});

app.get('/forgot-password', (req, res, next) => {
    res.sendFile(path.join(__dirname, 'static', 'forgot-password.html'));
});

app.post('/registerUser', async (req, res) => {
    const {
        employeeId, employeeName,
        mailId, password, userType, subLocation
    } = req.body;
    let hashedPassword = "";
    for (let i = 0; i < password.length; i++) {
        hashedPassword += process.env.secret_one + password.charCodeAt(i) + process.env.secret_two;
    }
    const query = `
        INSERT INTO Users (
            employeeId,employeeName,mailId,password,userType,subLocation
        ) VALUES (?,?,?,?,?,?)
    `;

    try {
        const [result] = await pool.execute(query, [
            employeeId, employeeName,
            mailId, hashedPassword, userType, subLocation
        ]);
        notifier.notify({
            title: 'Salutations!',
            message: 'User added successfully!!',
            icon: path.join(__dirname, 'icon.jpg'),
            sound: true,
            wait: true
        });
        res.status(201).json({ message: 'User added successfully', result });
    } catch (error) {

        console.error('Error inserting user:');
        res.status(500).json({ error: 'Failed to add user', details: error.message });
    }
});

app.put('/deleteUser', async (req, res) => {
    const {
        employeeId, employeeName
    } = req.body;
    const query = `
        UPDATE Users
        SET userStatus = 'Deactivated'
        WHERE employeeId = ? and employeeName = ?
    `;

    try {
        const [result] = await pool.execute(query, [
            employeeId, employeeName
        ]);
        notifier.notify({
            title: 'Salutations!',
            message: 'User deactivated successfully!!',
            icon: path.join(__dirname, 'icon.jpg'),
            sound: true,
            wait: true
        });
        res.status(201).json({ message: 'User deactivated successfully', result });
    } catch (error) {

        console.error('Error deactivating user:');
        res.status(500).json({ error: 'Failed to deactivate user', details: error.message });
    }
});

app.get('/users/display', async (req, res) => {

    const query = 'SELECT * FROM users';

    try {
        const [users] = await pool.execute(query);
        if (users.length > 0) {
            res.status(200).json(users);
        } else {
            res.status(404).json({ message: 'No users found.' });
        }
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ error: 'Failed to fetch user', details: error.message });
    }
});

app.put('/resetUsers', async (req, res) => {
    try {
        let query = `SET SQL_SAFE_UPDATES=0`;
        await pool.execute(query);
        query = `Update Users Set sessionStatus = 'Inactive'`;
        await pool.execute(query);
        query = `SET SQL_SAFE_UPDATES=1`;
        await pool.execute(query);
        res.status(200).json('All users are reseted successfully');
    } catch (error) {
        console.error('Error resetting users:', error);
        res.status(500).json({ error: 'Failed to reset users', details: error.message });
    }
});

app.post('/loginUser', async (req, res) => {
    const { employeeId, password } = req.body;
    let hashedPassword = "";
    for (let i = 0; i < password.length; i++) {
        hashedPassword += process.env.secret_one + password.charCodeAt(i) + process.env.secret_two;
    }
    const query = `SELECT * FROM Users WHERE employeeId = ? AND password = ?`;

    try {
        const [result] = await pool.execute(query, [employeeId, hashedPassword]);
        if (result.length > 0) {
            if (result[0].sessionStatus == 'Active') {
                return res.status(403).json({ message: 'Session limit reached' });
            }
            req.session.user = {
                employeeId: result[0].employeeId,
                employeeName: result[0].employeeName,
                subLocation: result[0].subLocation,
                userType: result[0].userType,
                userStatus: result[0].userStatus,
            };
            req.session.save();
            res.status(200).json({ message: 'Successful login', result });
        }
        else {
            res.status(401).json({ message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error finding user:', error);
        res.status(500).json({ error: 'Failed to find user', details: error.message });
    }
});

app.get('/sessionData', async (req, res) => {

    if (req.session.user) {
        res.json({
            employeeName: req.session.user.employeeName,
            employeeId: req.session.user.employeeId, subLocation: req.session.user.subLocation,
            userType: req.session.user.userType,
            userStatus: req.session.user.userStatus,
        });
    } else {
        res.json({ employeeName: null, employeeId: null, subLocation: null, userType: null });
    }
});

app.get('/logout', async (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out.');
        }
        res.sendFile(path.join(__dirname, 'static', 'signout.html'));
    });
});

app.post('/forgot-password', async (req, res, next) => {
    const mailId = req.body.mailId;

    try {
        const checkQuery = `SELECT * FROM users WHERE mailId = ?`;
        const [user] = await pool.query(checkQuery, [mailId]);
        if (user.length > 0) {
            const secret = JWT_SECRET + user[0].password;
            const payload = {
                mailId: user[0].mailId,
                employeeId: user[0].employeeId
            }
            const token = jwt.sign(payload, secret, { expiresIn: '360m' });
            const link = `http://localhost:${port}/reset-password/${user[0].employeeId}/${token}`;
            res.json({ link: link });
        } else {
            res.status(401).json({ message: 'Invalid Email Id' });
        }
    } catch (error) {
        console.error('Error finding user:', error);
        res.status(500).json({ error: 'Failed to find user', details: error.message });
    }
});

app.get('/reset-password/:employeeId/:token', async (req, res, next) => {
    const { employeeId, token } = req.params;
    const checkQuery = `SELECT * FROM users WHERE employeeId = ?`;
    const [user] = await pool.query(checkQuery, [employeeId]);
    if (!user || employeeId != user[0].employeeId) {
        res.send('Invalid Employee Id');
        return;
    }
    const secret = JWT_SECRET + user[0].password;
    try {
        const payload = jwt.verify(token, secret);
        res.sendFile(path.join(__dirname, 'static', 'reset-password.html'));
    } catch (error) {
        console.log(error.message)
        res.send(error.message);
    }
});

app.post('/reset-password/:employeeId/:token', async (req, res, next) => {
    const { employeeId, token } = req.params;
    let { pswd, confirmPswd } = req.body;
    const password = pswd;
    let hashedPassword = "";
    for (let i = 0; i < password.length; i++) {
        hashedPassword += process.env.secret_one + password.charCodeAt(i) + process.env.secret_two;
    }
    if (pswd != confirmPswd) {
        res.send('Password and Confirm Password does not match, Please re-enter your Password');
        return;
    }
    confirmPswd = hashedPassword;
    pswd = hashedPassword;
    const checkQuery = `SELECT * FROM users WHERE employeeId = ?`;
    const [user] = await pool.query(checkQuery, [employeeId]);
    if (employeeId != user[0].employeeId) {
        res.send('Invalid Employee Id');
        return;
    }
    const secret = JWT_SECRET + user[0].password;
    try {
        const payload = jwt.verify(token, secret);

        user[0].password = confirmPswd;

        let query = `SET SQL_SAFE_UPDATES=0`;
        await pool.execute(query);

        const checkQuery = `Update Users SET password = ? where employeeId = ?`;
        const [updatedUser] = await pool.query(checkQuery, [confirmPswd, employeeId]);

        query = `SET SQL_SAFE_UPDATES=1`;
        await pool.execute(query);
        notifier.notify({
            title: 'Salutations!',
            message: 'Password updated successfully!!',
            icon: path.join(__dirname, 'icon.jpg'),
            sound: true,
            wait: true
        });
        res.redirect('/signinUser');
    } catch (error) {
        console.log(error.message)
        res.send(error.message);
    }
});

app.post('/assets/add', async (req, res) => {
    const {
        location, subLocation, status, username, employeeId, assetType,
        assetMake, assetSerialNumber, assetModel, invoiceNumber, poNumber, amcInvoiceNumber,
        warrantyStatus, warrantyStartDate, warrantyEndDate, warrantyTenure,
        purchaseDate, purchaseYear, price, vendorName, contactNumber,
        mailId, processor, cpuSpeed, ramInstalled, hddCapacity, operatingSystem, osLicense, transactionDate, transactionCreatedDate
    } = req.body;

    const query = `
        INSERT INTO Assets (
            location, subLocation, status, username, employeeId, assetType,
            assetMake, assetSerialNumber, assetModel, invoiceNumber, poNumber, amcInvoiceNumber,
            warrantyStatus, warrantyStartDate, warrantyEndDate, warrantyTenure,
            purchaseDate, purchaseYear, price, vendorName, contactNumber, mailId,
            processor, cpuSpeed, ramInstalled, hddCapacity, operatingSystem, osLicense,transactionDate,transactionCreatedDate
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?,?,?)
    `;

    try {
        const [result] = await pool.execute(query, [
            location, subLocation, status, username, employeeId, assetType,
            assetMake, assetSerialNumber, assetModel, invoiceNumber, poNumber, amcInvoiceNumber,
            warrantyStatus, warrantyStartDate, warrantyEndDate, warrantyTenure,
            purchaseDate, purchaseYear, price, vendorName, contactNumber,
            mailId, processor, cpuSpeed, ramInstalled, hddCapacity, operatingSystem, osLicense, transactionDate, transactionCreatedDate
        ]);
        res.status(200).json({ message: 'Asset added successfully', result });
        notifier.notify({
            title: 'Salutations!',
            message: 'Asset added successfully!!',
            icon: path.join(__dirname, 'icon.jpg'),
            sound: true,
            wait: true
        });
    } catch (error) {
        console.error('Error inserting asset:', error);
        res.status(500).json({ error: 'Failed to add asset', details: error.message });
    }
});

app.post('/assets/search', async (req, res) => {
    const { location, subLocation, status, username, employeeId, assetType,
        assetMake, assetSerialNumber, assetModel, invoiceNumber, poNumber, amcInvoiceNumber,
        warrantyStatus, warrantyStartDate, warrantyEndDate, warrantyTenure,
        purchaseDate, purchaseYear, price, vendorName, contactNumber,
        mailId, processor, cpuSpeed, ramInstalled, hddCapacity, operatingSystem, osLicense } = req.body;

    let field, value;
    if (location) {
        field = 'location';
        value = location;
    } else if (subLocation) {
        field = 'subLocation';
        value = subLocation;
    } else if (status) {
        field = 'status';
        value = status;
    } else if (username) {
        field = 'username';
        value = username;
    } else if (employeeId) {
        field = 'employeeId';
        value = employeeId;
    } else if (assetType) {
        field = 'assetType';
        value = assetType;
    } else if (assetMake) {
        field = 'assetMake';
        value = assetMake;
    } else if (assetModel) {
        field = 'assetModel';
        value = assetModel;
    } else if (assetSerialNumber) {
        field = 'assetSerialNumber';
        value = assetSerialNumber;
    } else if (invoiceNumber) {
        field = 'invoiceNumber';
        value = invoiceNumber;
    } else if (poNumber) {
        field = 'poNumber';
        value = poNumber;
    } else if (amcInvoiceNumber) {
        field = 'amcInvoiceNumber';
        value = amcInvoiceNumber;
    } else if (warrantyStatus) {
        field = 'warrantyStatus';
        value = warrantyStatus;
    } else if (warrantyStartDate) {
        field = 'warrantyStartDate';
        value = warrantyStartDate;
    } else if (warrantyEndDate) {
        field = 'warrantyEndDate';
        value = warrantyEndDate;
    } else if (warrantyTenure) {
        field = 'warrantyTenure';
        value = warrantyTenure;
    } else if (purchaseDate) {
        field = 'purchaseDate';
        value = purchaseDate;
    } else if (purchaseYear) {
        field = 'purchaseYear';
        value = purchaseYear;
    } else if (price) {
        field = 'price';
        value = price;
    } else if (vendorName) {
        field = 'vendorName';
        value = vendorName;
    } else if (contactNumber) {
        field = 'contactNumber';
        value = contactNumber;
    } else if (mailId) {
        field = 'mailId';
        value = mailId;
    } else if (processor) {
        field = 'processor';
        value = processor;
    } else if (cpuSpeed) {
        field = 'cpuSpeed';
        value = cpuSpeed;
    } else if (ramInstalled) {
        field = 'ramInstalled';
        value = ramInstalled;
    } else if (hddCapacity) {
        field = 'hddCapacity';
        value = hddCapacity;
    } else if (operatingSystem) {
        field = 'operatingSystem';
        value = operatingSystem;
    } else if (osLicense) {
        field = 'osLicense';
        value = osLicense;
    } else {
        return res.status(400).json({ error: 'At least one search field is required.' });
    }

    const query = `SELECT * FROM Assets WHERE ${field} like ?`;

    try {
        const [assets] = await pool.execute(query, [`%${value}%`]);

        if (assets.length > 0) {
            res.status(200).json(assets);
        } else {
            res.status(404).json({ message: 'No asset found with this search criteria.' });
        }
    } catch (error) {
        console.error('Error fetching asset:', error);
        res.status(500).json({ error: 'Failed to fetch asset', details: error.message });
    }
});

app.post('/assets/search/specific', async (req, res) => {
    const { assetSerialNumber, searchField } = req.body;

    if (!assetSerialNumber || !searchField) {
        return res.status(400).json({ message: 'Asset serial number and search field are required.' });
    }

    const query = `SELECT * FROM assets WHERE assetSerialNumber = ?`;
    try {
        const [assets] = await pool.execute(query, [assetSerialNumber]);
        if (assets.length > 0) {
            res.status(200).json(assets);
        } else {
            res.status(404).json({ message: 'No asset found with this search criteria.' });
        }
    } catch (error) {
        console.error('Error fetching asset:', error);
        res.status(500).json({ error: 'Failed to fetch asset', details: error.message });
    }
});

app.put('/assets/update/:_assetSerialNumber/:subLocation/:userType', async (req, res) => {
    const assetSerialNumber = req.params._assetSerialNumber;
    const subLocation = req.params.subLocation;
    const userType = req.params.userType;
    const fields = req.body;

    const updates = [];
    const values = [];

    const fieldNames = [
        'location', 'subLocation', 'status', 'username',
        'employeeId', 'assetType', 'assetMake', 'assetModel',
        'warrantyStatus', 'warrantyStartDate', 'warrantyEndDate',
        'warrantyTenure', 'vendorName', 'contactNumber',
        'mailId', 'processor', 'cpuSpeed', 'ramInstalled',
        'hddCapacity', 'operatingSystem', 'osLicense', 'transactionDate'
    ];

    fieldNames.forEach((field) => {
        if (fields[field] !== undefined && fields[field] !== '') {
            updates.push(`${field} = ?`);
            values.push(fields[field]);
        }
    });

    if (updates.length === 0) {
        return res.status(400).json({ success: false, message: 'No valid fields provided for update.' });
    }

    const checkQuery = `SELECT * FROM assets WHERE assetSerialNumber = ?`;
    const [checkResult] = await pool.query(checkQuery, [assetSerialNumber]);
    if (checkResult.length === 0) {
        return res.status(404).json({ success: false, message: 'Asset not found.' });
    }
    if (checkResult[0].subLocation != subLocation && userType == 'user') {
        return res.status(404).json({ success: false, message: 'You cannot update asset of other locations' });
    }

    const query = `
        UPDATE assets 
        SET ${updates.join(', ')}
        WHERE assetSerialNumber = ?
    `;

    values.push(assetSerialNumber);

    try {
        let safeQuery = `SET SQL_SAFE_UPDATES=0`;
        await pool.execute(safeQuery);
        const [result] = await pool.query(query, values);
        safeQuery = `SET SQL_SAFE_UPDATES=1`;
        await pool.execute(safeQuery);
        if (result.affectedRows > 0) {
            res.json({ success: true, message: 'Asset updated successfully!' });
            notifier.notify({
                title: 'Salutations!',
                message: 'Asset updated successfully!!',
                icon: path.join(__dirname, 'icon.jpg'),
                sound: true,
                wait: true
            });
        } else {
            res.status(404).json({ success: false, message: 'Asset not found.' });
        }

    } catch (error) {
        console.error('Error updating asset:', error);
        res.status(500).json({ success: false, message: 'Error updating asset.' });
    }
});

app.get('/assets/display', async (req, res) => {

    const query = 'SELECT * FROM Assets';

    try {
        const [assets] = await pool.execute(query);
        if (assets.length > 0) {
            res.status(200).json(assets);
        } else {
            res.status(404).json({ message: 'No assets found.' });
        }
    } catch (error) {
        console.error('Error fetching asset:', error);
        res.status(500).json({ error: 'Failed to fetch asset', details: error.message });
    }
});


app.get('/assets/downloadAssets/:subLocation', async (req, res) => {
    const subLocation = req.params.subLocation;
    try {
        var results = [];
        if (subLocation != 'All Data') {
            const checkQuery = `SELECT * FROM assets WHERE subLocation like ?`;
            [results] = await pool.query(checkQuery, [`%${subLocation}%`]);
        }
        else {
            const checkQuery = `SELECT * FROM assets`;
            [results] = await pool.query(checkQuery);
        }


        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'No Assets found for this location' });
        }
        var data = [["Location", "Sub Location", "Status", "Employee ID",
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
        var worksheet = xlsx.utils.aoa_to_sheet(data),
            workbook = xlsx.utils.book_new();



        xlsx.utils.book_append_sheet(workbook, worksheet, "Assets");
        const excelBuffer = xlsx.write(workbook, { bookType: 'xlsx', type: 'buffer' });

        res.setHeader('Content-Disposition', 'attachment; filename=assets.xlsx');
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

        res.status(200).send(excelBuffer);

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
        res.status(500).json({ message: 'Error generating Excel file' });
    }
});


app.put('/assets/delete/:assetSerialNumber', async (req, res) => {
    const assetSerialNumber = req.params.assetSerialNumber;
    const transactionDate = req.body.transactionDate;
    const userType = req.body.userType;
    const values = [];

    const checkQuery = `SELECT * FROM assets WHERE assetSerialNumber = ?`;
    const [checkResult] = await pool.query(checkQuery, [assetSerialNumber]);

    if (checkResult.length === 0) {
        return res.status(404).json({ success: false, message: 'Asset not found.' });
    }
    if (userType == 'user') {
        return res.status(404).json({ success: false, message: 'You are not authorized to delete asset.' });
    }


    const query = `
        UPDATE assets SET status='Scrap' , transactionDate = ? WHERE assetSerialNumber = ? 
    `;
    values.push(transactionDate);
    values.push(assetSerialNumber);

    try {
        let safeQuery = `SET SQL_SAFE_UPDATES=0`;
        await pool.execute(safeQuery);
        const [result] = await pool.query(query, values);
        safeQuery = `SET SQL_SAFE_UPDATES=1`;
        await pool.execute(safeQuery);
        if (result.affectedRows > 0) {
            notifier.notify({
                title: 'Salutations!',
                message: 'Asset deleted successfully!!',
                icon: path.join(__dirname, 'icon.jpg'),
                sound: true,
                wait: true
            });
            res.status(200).json({ success: true, message: 'Asset deleted successfully' });
        } else {
            res.status(401).json({ success: false, message: 'You cannot delete asset of other location.' });
        }
    } catch (error) {
        console.error('Error updating asset:', error);
        res.status(500).json({ success: false, message: 'Error updating asset.' });
    }
});

app.put('/issueAsset/:userType/:subLocation', async (req, res) => {
    const assetSerialNumber = req.body.__assetSerialNumber;
    const employeeId = req.body.__employeeId;
    const username = req.body.__username;
    const userType = req.params.userType;
    const subLocation = req.params.subLocation;
    const values = [];
    values.push(employeeId);
    values.push(username);
    values.push(assetSerialNumber);

    const checkQuery = `SELECT * FROM assets WHERE assetSerialNumber = ?`;
    const [checkResult] = await pool.query(checkQuery, [assetSerialNumber]);

    if (checkResult.length === 0) {
        return res.status(404).json({ success: false, message: 'Asset not found.' });
    }
    if (checkResult[0].subLocation != subLocation && userType == 'user') {
        return res.status(404).json({ success: false, message: 'You cannot issue asset of other locations' });
    }

    try {
        let safeQuery = `SET SQL_SAFE_UPDATES=0`;
        await pool.execute(safeQuery);
        let query = `Update Assets SET employeeId = ? , username = ? where assetSerialNumber = ?`;
        await pool.query(query, values);
        safeQuery = `SET SQL_SAFE_UPDATES=1`;
        await pool.execute(safeQuery);
        notifier.notify({
            title: 'Salutations!',
            message: 'Asset issued successfully!!',
            icon: path.join(__dirname, 'icon.jpg'),
            sound: true,
            wait: true
        });
        res.status(200).json({ success: true, message: 'Asset issued successfully' });
    } catch (error) {
        console.error('Error resetting users:', error);
        res.status(500).json({ error: 'Failed to reset users', details: error.message });
    }
});


app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});