require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const morgan = require('morgan');
const { name } = require('ejs');

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(helmet());
app.use(morgan('tiny')); // For logging HTTP requests

// Configure MySQL connection
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});
// Token generator function
const generateToken = (user) => {
  return jwt.sign(
    { userId: user.unique_id, email: user.mail, role: user.role },
    'your_jwt_secret',
    { expiresIn: '24h' }
  );
};

// Signup Endpoint
app.post('/api/signup', (req, res) => {
  const { name, age, gender, email, address, phone_no, password, insta } = req.body;

  db.promise().query('SELECT * FROM Total WHERE mail = ?', [email])
    .then(([rows]) => {
      if (rows.length > 0) {
        return res.status(409).json({ message: 'Email already in use' });
      }

      return bcrypt.hash(password, 10);
    })
    .then(hashedPassword => {
      return db.promise().query('INSERT INTO Total (name, age, gender, mail, address, phone_no, password, insta) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  [name, age, gender, email, address, phone_no, hashedPassword, insta]);

    })
    .then(([result]) => {
      const token = generateToken({ unique_id: result.insertId, mail: email });
      res.status(201).json({ message: 'User signed up successfully', token, unique_id: result.insertId });
    })
    .catch(error => {
      res.status(500).json({ message: 'Error signing up', error: error.message });
    });
});


// Login Endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.promise().query('SELECT * FROM Total WHERE mail = ?', [email]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'Password is incorrect' });
    }

    const token = generateToken(user);
    res.json({ message: 'Logged in successfully', token, userId: user.unique_id, name: user.name, role: user.role });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Middleware to verify token (assuming token contains role and unique_id)
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(403).send('A token is required for authentication');
  try {
      const decoded = jwt.verify(token, 'your_jwt_secret');
      req.user = decoded;
  } catch (err) {
      return res.status(401).send('Invalid Token');
  }
  return next();
};

// Check role middleware
const checkRole = (role) => {
  return (req, res, next) => {
      if (req.user.role !== role) {
          return res.status(403).send('Unauthorized');
      }
      next();
  };
};

app.post('/api/classes', verifyToken, async (req, res) => {
  const { userId, newScheduledClasses } = req.body;

  try {
    // Use the exact date provided by the frontend
    const values = newScheduledClasses.map(cls => [
      cls.program_type,  // Pass program_type
      cls.day,
      cls.slot,
      cls.status,
      cls.unique_id,  // Pass unique_id
      cls.date // Use the date provided
    ]);

    const sql = 'INSERT INTO TTC.ClassBookings (program_type, day, time_slot, status, unique_id, class_date) VALUES ?';
    db.query(sql, [values], (error, result) => {
      if (error) {
        res.status(500).json({ message: 'Error booking classes', error: error.message });
      } else {
        res.status(201).json({ message: 'Classes booked successfully', bookingCount: result.affectedRows });
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Booking failed', error: error.message });
  }
});


app.get('/api/studentsWithPrograms', verifyToken, checkRole('Admin'), async (req, res) => {
  try {
    // Fetch all students from Total table
    const [students] = await db.promise().query('SELECT * FROM Total');

    // Fetch enrollments from the TTC.Enroll table
    const [enrollments] = await db.promise().query(`
      SELECT 
        unique_id, 
        program_type, 
        sessions_attended AS sessions, 
        sessions_enrolled AS total_classes, 
        level 
      FROM TTC.Enroll
    `);

    // Map enrollments by student ID
    const enrollmentsByStudent = {};
    enrollments.forEach((enrollment) => {
      if (!enrollmentsByStudent[enrollment.unique_id]) {
        enrollmentsByStudent[enrollment.unique_id] = [];
      }
      enrollmentsByStudent[enrollment.unique_id].push(enrollment);
    });

    // Combine student data with enrollments
    const studentsWithPrograms = students.map((student) => {
      const studentEnrollments = enrollmentsByStudent[student.unique_id] || [];
      return {
        unique_id: student.unique_id,
        name: student.name,
        age: student.age,
        gender: student.gender,
        address: student.address,
        mail: student.mail,
        phone_no: student.phone_no,
        insta: student.insta,
        programs: studentEnrollments.map((e) => e.program_type),
        sessions: studentEnrollments.map((e) => e.sessions),
        totalClasses: studentEnrollments.map((e) => e.total_classes),
        levels: studentEnrollments.map((e) => e.level),
      };
    });

    res.json(studentsWithPrograms);
  } catch (error) {
    console.error('Error fetching students with programs:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/classes/:booking_id/:unique_id', verifyToken, checkRole('Admin'), async (req, res) => {
  const { status } = req.body; // The new status to be set
  const { booking_id, unique_id } = req.params; // The unique user ID from the request parameters

  try {
    // Fetch the existing class booking to get the current status based on unique_id
    const [existingBooking] = await db.promise().query(
      'SELECT status FROM ClassBookings WHERE unique_id = ?',
      [unique_id]
    );

    // Check if the booking exists for the given unique_id
    if (existingBooking.length === 0) {
      return res.status(404).json({ message: 'Class booking not found for the given unique_id' });
    }

    const currentStatus = existingBooking[0].status;

    // Retrieve the program_type directly from the TTC.Enroll table using unique_id
    const [enrollment] = await db.promise().query(
      'SELECT program_type FROM TTC.Enroll WHERE unique_id = ?',
      [unique_id]
    );

    // If no enrollment found, return an error
    if (enrollment.length === 0) {
      return res.status(404).json({ message: `No enrollment found for unique_id: ${unique_id}` });
    }

    // Get the program_type from the enrollment query
    const programType = enrollment[0].program_type;

    // Update class status in ClassBookings table using unique_id
    await db.promise().query(
      'UPDATE ClassBookings SET status = ? WHERE unique_id = ? and booking_id = ?',
      [status, unique_id, booking_id]
    );

    // Respond with a success message
    res.json({ message: 'Class status updated successfully' });
  } catch (err) {
    console.error('Error updating class status:', err);
    return res.status(500).json({ message: 'Error updating class status', error: err.message });
  }
});


app.post('/api/joinProgram', verifyToken, async (req, res) => {
  const { programType, unique_id, sessions_enrolled } = req.body;

  try {
    // Check if the user is already enrolled in the TTC.Enroll table
    const [existingEnrollment] = await db.promise().query(
      `SELECT * FROM TTC.Enroll WHERE unique_id = ? AND program_type = ?`,
      [unique_id, programType]
    );

    if (existingEnrollment.length > 0) {
      // If enrolled in the TTC.Enroll table, update sessions_enrolled and reset sessions_attended
      await db.promise().query(
        `UPDATE TTC.Enroll SET sessions_enrolled = ?, sessions_attended = 0 WHERE unique_id = ? AND program_type = ?`,
        [sessions_enrolled, unique_id, programType]
      );
    } else {
      // If not enrolled in the TTC.Enroll table, insert a new record
      await db.promise().query(
        `INSERT INTO TTC.Enroll (unique_id, program_type, sessions_enrolled, sessions_attended) VALUES (?, ?, ?, 0)`,
        [unique_id, programType, sessions_enrolled]
      );
    }

    res.status(201).json({ message: 'Successfully joined the program and enrollment details recorded.' });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ message: 'Failed to join program', error: error.message });
  }
});

app.get('/api/scheduledClasses', verifyToken, (req, res) => {
  // If the user is an admin, fetch all bookings; otherwise, fetch only their bookings.
  const isAdmin = req.user.role === 'Admin';
  const { status } = req.query;
  let sql;
  let params;

  if (isAdmin) {
      sql = `
          SELECT cb.*, t.name 
          FROM ClassBookings cb
          JOIN Total t ON t.unique_id = cb.unique_id
          WHERE cb.attended = 0 
          ORDER BY cb.day, cb.time_slot, cb.class_date;
      `;
      params = status ? [status] : [];
  } else {
      sql = `
          SELECT cb.*, t.name 
          FROM ClassBookings cb
          JOIN Total t ON t.unique_id = cb.unique_id
          WHERE cb.unique_id = ? AND cb.attended = 0
          ORDER BY cb.day, cb.time_slot, cb.class_date;
      `;
      params = [req.user.userId];
  }

  db.query(sql, params, (error, results) => {
      if (error) {
          return res.status(500).json({ message: 'Error fetching classes', error: error.message });
      }
      if (results.length === 0) {
          return res.status(404).json({ message: 'No classes found' });
      }
      
      res.json(results);
  });
});

app.post('/api/update-bookings', async (req, res) => {
  const { bookingIds, newStatus } = req.body; // `bookingIds` should be an array of `booking_id`s and `newStatus` could be 'booked' or 'not-booked'

  if (!Array.isArray(bookingIds) || bookingIds.length === 0) {
      return res.status(400).json({ message: "No booking IDs provided" });
  }

  const placeholders = bookingIds.map(() => '?').join(', '); // Create placeholders for SQL query
  const sql = `UPDATE TTC.ClassBookings SET status = ? WHERE booking_id IN (${placeholders})`;

  db.query(sql, [newStatus, ...bookingIds], (error, result) => {
      if (error) {
          console.error('Error updating booking slots:', error);
          res.status(500).json({ message: 'Error updating booking slots', error: error.message });
      } else {
          res.json({ message: 'Booking slots updated successfully', affectedRows: result.affectedRows });
      }
  });
});

app.get('/api/classes/count/:userId', (req, res) => {
  const userId = req.params.userId;

  const query = 'SELECT COUNT(*) AS count FROM TTC.ClassBookings WHERE user_id = ? AND status IN ("booked", "pending")';

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching booked classes count:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
    res.json({ count: results[0].count });
  });
});


app.get('/api/unavailable-slots', (req, res) => {
  const query = 'SELECT day, slots, Date FROM TTC.Unavailable';

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching unavailable slots:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
    res.json(results);
  });
});


app.post('/api/update-slots', (req, res) => {
  const { slotsToMakeAvailable, slotsToMakeUnavailable } = req.body;

  if (
    (!slotsToMakeAvailable || !Array.isArray(slotsToMakeAvailable)) &&
    (!slotsToMakeUnavailable || !Array.isArray(slotsToMakeUnavailable))
  ) {
    return res.status(400).json({ message: 'Invalid request data' });
  }

  const promises = [];

  // Handle making slots unavailable
  if (slotsToMakeUnavailable && slotsToMakeUnavailable.length > 0) {
    const values = slotsToMakeUnavailable.map((slotKey) => {
      const [day, slot, dateStr] = slotKey.split('|');
      const date = dateStr.trim(); // Date in 'YYYY-MM-DD' format
      return [day.trim(), slot.trim(), date];
    });

    const insertQuery = 'INSERT INTO TTC.Unavailable (day, slots, Date) VALUES ?';

    const insertPromise = new Promise((resolve, reject) => {
      db.query(insertQuery, [values], (err) => {
        if (err) {
          console.error('Error inserting unavailable slots:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });

    promises.push(insertPromise);
  }

  // Handle making slots available
  if (slotsToMakeAvailable && slotsToMakeAvailable.length > 0) {
    const conditions = slotsToMakeAvailable.map(() => '(day = ? AND slots = ? AND Date = ?)').join(' OR ');
    const params = [];
    slotsToMakeAvailable.forEach((slotKey) => {
      const [day, slot, dateStr] = slotKey.split('|');
      const date = dateStr.trim();
      params.push(day.trim(), slot.trim(), date);
    });

    const deleteQuery = `DELETE FROM TTC.Unavailable WHERE ${conditions}`;

    const deletePromise = new Promise((resolve, reject) => {
      db.query(deleteQuery, params, (err) => {
        if (err) {
          console.error('Error deleting available slots:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });

    promises.push(deletePromise);
  }

  Promise.all(promises)
    .then(() => res.json({ message: 'Slots updated successfully' }))
    .catch((error) => res.status(500).json({ message: 'Internal server error', error: error.message }));
});


app.get('/api/program-students', verifyToken, checkRole('Admin'), async (req, res) => {
  const { programType } = req.query;

  try {
    // Construct the query dynamically to get program-specific students
    const sql = `
      SELECT e.unique_id, e.sessions_attended AS sessions, e.sessions_enrolled AS total_classes, s.name, e.level
      FROM TTC.Enroll AS e 
      INNER JOIN Total AS s ON e.unique_id = s.unique_id
      WHERE e.program_type = ?;
    `;

    // Execute the query with programType parameter
    const [students] = await db.promise().query(sql, [programType]);
    res.json(students);
  } catch (error) {
    console.error('Database error:', error.message);
    res.status(500).json({ message: 'Failed to fetch students', error: error.message });
  }
});

app.post('/api/update-student-level', verifyToken, checkRole('Admin'), async (req, res) => {
  const { unique_id, programType, newLevel } = req.body;

  try {
    const sql = `UPDATE TTC.Enroll SET level = ? WHERE unique_id = ? AND program_type = ?`;
    await db.promise().query(sql, [newLevel, unique_id, programType]);
    res.json({ message: 'Student level updated successfully' });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ message: 'Failed to update student level', error: error.message });
  }
});


app.get('/api/sessions/:userId', async (req, res) => {
  const { userId } = req.params;

  // SQL query to get sessions data from the TTC.Enroll table
  const query = `
    SELECT program_type, sessions_attended AS sessions, sessions_enrolled AS total_classes
    FROM TTC.Enroll
    WHERE unique_id = ?
  `;

  try {
    // Use `db.promise().query` instead of `pool.query`
    const [result] = await db.promise().query(query, [userId]);

    // Return the fetched session data
    res.status(200).json(result);
  } catch (error) {
    console.error('Error fetching sessions data:', error);
    res.status(500).json({ message: 'Failed to fetch sessions data.' });
  }
});


app.get('/api/profile/info', async (req, res) => {
  const { userId } = req.query; // Assuming you're passing the user's ID as a query parameter

  try {
      const sql = 'SELECT name, age, gender, mail AS email, address, insta, phone_no FROM Total WHERE unique_id = ?';
      const results = await db.promise().query(sql, [userId]);

      if (results[0].length > 0) {
          res.json(results[0][0]);
      } else {
          res.status(404).json({ message: 'User not found' });
      }
  } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.post('/api/profile/update', async (req, res) => {
  const { userId, name, age, gender, email, address, phone_no, insta} = req.body;

  try {
      const sql = 'UPDATE Total SET name = ?, age = ?, gender = ?, mail = ?, address = ?, phone_no = ?, insta = ? WHERE unique_id = ?';
      await db.promise().query(sql, [name, age, gender, email, address, phone_no, insta, userId]);
      res.json({ message: 'Profile updated successfully' });
  } catch (error) {
      res.status(500).json({ message: 'Failed to update profile', error: error.message });
  }
});

app.get('/api/classes/upcoming', async (req, res) => {
  try {
    let { userId, page, limit } = req.query;

    // Ensure userId is an integer
    userId = parseInt(userId);
    if (isNaN(userId)) {
      return res.status(400).json({ message: 'Invalid User ID provided' });
    }

    page = parseInt(page) || 1;
    limit = parseInt(limit) || 14;

    const offset = (page - 1) * limit;

    let sql, sqlParams = [];
    let totalSql, totalParams = [];
    let totalResults, results;

    // Fetch data based on role (admin vs user)
    if (userId === 5) { // Assuming userId 5 is an admin ID
      // Fetch total count of all classes where attended is not 1
      totalSql = 'SELECT COUNT(*) AS total FROM ClassBookings WHERE attended = 0';
      [totalResults] = await db.promise().query(totalSql);

      // Fetch classes with pagination and exclude attended classes
      sql = `
        SELECT cb.booking_id, cb.day, cb.time_slot, cb.status, cb.class_date, t.name, t.unique_id, program_type
        FROM ClassBookings cb
        JOIN TTC.Total t ON cb.unique_id = t.unique_id
        WHERE cb.attended = 0  -- Exclude attended classes
        ORDER BY cb.booking_id DESC
        LIMIT ? OFFSET ?
      `;
      sqlParams = [limit, offset];
    } else {
      // Fetch total count for specific user, excluding attended classes
      totalSql = 'SELECT COUNT(*) AS total FROM ClassBookings WHERE unique_id = ? AND attended = 0';
      totalParams = [userId];
      [totalResults] = await db.promise().query(totalSql, totalParams);

      // Fetch classes for specific user, excluding attended classes
      sql = `
        SELECT cb.booking_id, cb.day, cb.time_slot, cb.status, cb.class_date, t.name, t.unique_id, program_type
        FROM ClassBookings cb
        JOIN TTC.Total t ON cb.unique_id = t.unique_id
        WHERE cb.unique_id = ? AND cb.attended = 0  -- Exclude attended classes
        ORDER BY cb.booking_id DESC
        LIMIT ? OFFSET ?
      `;
      sqlParams = [userId, limit, offset];
    }

    // Execute queries
    [results] = await db.promise().query(sql, sqlParams);
    const total = totalResults[0]?.total || 0;

    res.json({
      classes: results,
      total,
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error fetching upcoming classes',
      error: error.message,
    });
  }
});

  app.get('/api/completedClasses', verifyToken, (req, res) => { 
    const isAdmin = req.user.role === 'Admin';
    let sql;
    let params;
  
    if (isAdmin) {
      sql = `
        SELECT cb.*, t.name 
        FROM ClassBookings cb
        JOIN Total t ON t.unique_id = cb.unique_id
        WHERE cb.attended = 1
        ORDER BY cb.class_date DESC;
      `;
      params = [];
    } else {
      sql = `
        SELECT cb.*, t.name 
        FROM ClassBookings cb
        JOIN Total t ON t.unique_id = cb.unique_id
        WHERE cb.unique_id = ? AND cb.attended = 1
        ORDER BY cb.class_date DESC;
      `;
      params = [req.user.userId];
    }
  
    db.query(sql, params, (error, results) => {
      if (error) {
        return res.status(500).json({ message: "Error retrieving completed classes", error: error.message });
      }
      res.json(results);
    });
  });

  app.get('/api/programs/enrolled/:userId', (req, res) => {
    const { userId } = req.params;
  
    // SQL to fetch enrolled programs directly from the TTC.Enroll table.
    const sql = `
      SELECT program_type, sessions_attended AS sessions, sessions_enrolled AS total_classes
      FROM TTC.Enroll 
      WHERE unique_id = ?;
    `;
  
    // Execute the query and handle the response.
    db.query(sql, [userId], (err, results) => {
      if (err) {
        res.status(500).json({ message: 'Error retrieving enrolled programs', error: err });
      } else {
        const enrolledPrograms = results.map((result) => ({
          program_type: result.program_type,
          sessions: result.sessions,
          totalClasses: result.total_classes,
        }));
  
        res.status(200).json({
          userId,
          enrolledPrograms,
        });
      }
    });
  });

  app.post('/api/markCompleted', verifyToken, async (req, res) => {
    const { bookingId } = req.body;
    const userId = req.user.userId; // The ID of the logged-in user
    const isAdmin = req.user.role === 'Admin';
  
    try {
      // Check if the class exists and belongs to the user or if the user is an admin
      const [classDetails] = await db.promise().query(
        'SELECT unique_id, program_type FROM ClassBookings WHERE booking_id = ?',
        [bookingId]
      );
  
      if (classDetails.length === 0) {
        return res.status(404).json({ message: 'Class not found.' });
      }
  
      const classOwner = classDetails[0].unique_id;
      const programType = classDetails[0].program_type;
  
      // If the user is not an admin and not the owner of the class, deny access
      if (!isAdmin && classOwner !== userId) {
        return res.status(403).json({ message: 'Unauthorized action: You can only mark your own classes as completed.' });
      }
  
      // Mark the class as completed (set attended = 1)
      const updateClassBookingQuery = `UPDATE ClassBookings SET attended = 1 WHERE booking_id = ?;`;
      const [updateResult] = await db.promise().query(updateClassBookingQuery, [bookingId]);
  
      if (updateResult.affectedRows === 0) {
        return res.status(404).json({ message: 'No such class found or update not needed.' });
      }
  
      // Increment sessions_attended in the TTC.Enroll table for the user and program
      const updateSessionsQuery = `
        UPDATE TTC.Enroll
        SET sessions_attended = sessions_attended + 1
        WHERE unique_id = ? AND program_type = ?;
      `;
      await db.promise().query(updateSessionsQuery, [classOwner, programType]);
  
      res.json({ message: 'Class marked as completed successfully.' });
    } catch (error) {
      console.error('Error updating class status:', error);
      return res.status(500).json({ message: 'Failed to mark class as complete.', error: error.message });
    }
  });
  
  
 
// Endpoint to confirm payment
app.post('/api/confirmPayment', verifyToken, (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ message: 'Unauthorized action' });
  }

  const { bookingId } = req.body;
  const sql = `
    UPDATE ClassBookings
    SET paid = 1
    WHERE booking_id = ? AND attended = 1;
  `;

  db.query(sql, [bookingId], (error, result) => {
    if (error) {
      return res.status(500).json({ message: "Error updating payment status", error: error.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'No such class found or payment already confirmed' });
    }
    res.json({ message: 'Payment confirmed successfully' });
  });
});

app.delete('/api/enrollment/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;

  try {
    // Delete the enrollment directly from the TTC.Enroll table
    const [deleteResult] = await db.promise().query(
      'DELETE FROM TTC.Enroll WHERE unique_id = ?',
      [userId]
    );

    if (deleteResult.affectedRows === 0) {
      return res.status(404).json({ message: 'Enrollment not found for this user' });
    }

    res.json({ message: 'Enrollment canceled successfully' });
  } catch (error) {
    console.error('Error deleting enrollment:', error);
    res.status(500).json({ message: 'Error deleting enrollment', error: error.message });
  }
});

// all students
app.get('/api/students', (req, res) => {
  const query = `SELECT name, age, gender, address, insta, mail, phone_no FROM Total`;

  db.query(query, (err, results) => {
      if (err) {
          console.error('Error fetching students data:', err);
          res.status(500).send('Error retrieving data');
      } else {
          // Send the results as JSON
          res.json(results);
      }
  });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
