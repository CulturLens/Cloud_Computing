const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const db = require("../config/db"); // Database connection
const upload = require("../config/storage"); // File upload configuration
const { body, validationResult } = require("express-validator");

// =================== Middleware ===================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Access token required" });

  jwt.verify(token, "your_secret_key", (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user; // Menyimpan user yang didekode ke dalam req.user
    next();
  });
};

// =================== CRUD USER ===================

// POST: Register User
router.post(
  "/register",
  upload.single("photo"), // Menambahkan middleware untuk upload foto
  [
    body("name").notEmpty().withMessage("Name is required"),
    body("email").isEmail().withMessage("Valid email is required"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
    body("username").notEmpty().withMessage("Username is required"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password, username } = req.body;
    // Jika foto tidak di-upload, set null
    const profilePhoto = req.file ? req.file.path : null;  

    // Hash password sebelum menyimpannya
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `INSERT INTO users (name, email, password, username, profilePhoto) VALUES (?, ?, ?, ?, ?)`;

    db.query(query, [name, email, hashedPassword, username, profilePhoto], (err, result) => {
      if (err) return res.status(500).json({ message: "Error registering user", error: err });
      res.status(201).json({ message: "User registered successfully" });
    });
  }
);

// GET: Get All Users
router.get("/users", (req, res) => {
  const query = `SELECT id, name, email, username, profilePhoto, phone FROM users`;
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({
        message: "Error fetching users",
        error: err,
        timestamp: new Date().toISOString(),
      });
    }

    // Base URL untuk gambar profil
    const baseUrl = `${req.protocol}://${req.get("host")}/uploads`;
    const users = results.map(user => ({
      id: user.id,
      name: user.name,
      email: user.email,
      username: user.username,
      profilePhotoUrl: user.profilePhoto
        ? `${baseUrl}/${user.profilePhoto.replace(/\s+/g, "_")}` // Ganti spasi di respons
        : null,
      phone: user.phone,
    }));

    res.status(200).json({
      message: "Users fetched successfully",
      timestamp: new Date().toISOString(),
      users,
    });
  });
});


// GET: Get User by ID
router.get("/user/:id", (req, res) => {
  const { id } = req.params;

  const query = `SELECT id, name, email, username, profilePhoto, phone FROM users WHERE id = ?`;
  db.query(query, [id], (err, result) => {
    if (err) return res.status(500).json({ message: "Error fetching user data", error: err });

    if (result.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    // Base URL untuk gambar profil
    const baseUrl = `${req.protocol}://${req.get("host")}/uploads`;
    const user = result[0];
    user.profilePhotoUrl = user.profilePhoto
      ? `${baseUrl}/${user.profilePhoto.replace(/\s+/g, "_")}`  // Ganti spasi dengan "_"
      : null; // Fallback jika profilePhoto null

    res.status(200).json(user);
  });
});

//PUT User By Id
  router.put(
    "/user/:id",
    upload.single("profilePhoto"), 
    [
      body("phone").optional().isMobilePhone().withMessage("Valid phone number is required"), 
    ],
    async (req, res) => {
      const { id } = req.params;
      const { phone, password } = req.body;
      const photo = req.file ? req.file.path : null;
  
      // Ambil data user dari database untuk validasi
      db.query("SELECT username, email, password, phone, profilePhoto FROM users WHERE id = ?", [id], (err, result) => {
        if (err) {
          return res.status(500).json({ message: "Error fetching user data", error: err });
        }
        if (result.length === 0) {
          return res.status(404).json({ message: "User not found" });
        }
  
        const currentUser = result[0];
  
        // Validasi bahwa username dan email tidak berubah
        if (req.body.username && req.body.username !== currentUser.username) {
          return res.status(400).json({ message: "Username cannot be changed" });
        }
  
        if (req.body.email && req.body.email !== currentUser.email) {
          return res.status(400).json({ message: "Email cannot be changed" });
        }
  
        const updateFields = [];
        const updateValues = [];
  
        // Validasi perubahan password
        if (password) {
          // Hash password baru jika diubah
          // Gunakan bcrypt atau metode lainnya untuk hash password sebelum update
          const hashedPassword = bcrypt.hashSync(password, 10);  // Misalnya menggunakan bcrypt untuk hashing
          updateFields.push("password = ?");
          updateValues.push(hashedPassword);
        }
  
        // Validasi phone
        if (phone && phone !== currentUser.phone) {
          updateFields.push("phone = ?");
          updateValues.push(phone);
        }
  
        // Validasi profile photo
        if (photo && photo !== currentUser.profilePhoto) {
          updateFields.push("profilePhoto = ?");
          updateValues.push(photo);  
        }
  
        // Jika tidak ada perubahan
        if (updateFields.length === 0) {
          return res.status(400).json({ message: "No changes detected" });
        }
  
        updateValues.push(id);
  
        // Update data user di database
        const query = `UPDATE users SET ${updateFields.join(", ")} WHERE id = ?`;
  
        db.query(query, updateValues, (err, result) => {
          if (err) {
            return res.status(500).json({ message: "Error updating user", error: err });
          }
          if (result.affectedRows === 0) {
            return res.status(404).json({ message: "User not found" });
          }
          res.status(200).json({ message: "User updated successfully" });
        });
      });
    }
  );
  


// DELETE: Delete User and Associated Posts
router.delete("/user/:id", (req, res) => {
  const { id } = req.params;

  const deletePostsQuery = `DELETE FROM forums WHERE user_id = ?`;
  db.query(deletePostsQuery, [id], (err) => {
    if (err) {
      return res.status(500).json({ message: "Error deleting user posts", error: err });
    }

    const deleteCommentsQuery = `DELETE FROM comments WHERE user_id = ?`;
    db.query(deleteCommentsQuery, [id], (err) => {
      if (err) {
        return res.status(500).json({ message: "Error deleting user comments", error: err });
      }

      const deleteUserQuery = `DELETE FROM users WHERE id = ?`;
      db.query(deleteUserQuery, [id], (err, result) => {
        if (err) {
          return res.status(500).json({ message: "Error deleting user", error: err });
        }
        if (result.affectedRows === 0) {
          return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json({ message: "User and associated data deleted successfully" });
      });
    });
  });
});

// POST: Login User
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const query = `SELECT * FROM users WHERE email = ?`;
  db.query(query, [email], async (err, result) => {
    if (err || result.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const user = result[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Create JWT tokens
    const token = jwt.sign({ id: user.id, name: user.name }, "your_secret_key", { expiresIn: "1h" });
    const refreshToken = jwt.sign({ id: user.id, name: user.name }, "your_refresh_secret_key", { expiresIn: "7d" });

    // Return response with user details and registration time
    res.json({
      message: "Login successful",
      token: token,
      refreshToken: refreshToken,
      user: {
        id: user.id,
        name: user.name,
        username: user.username,
        email: user.email,
        registrationTime: user.created_at, // Assuming 'created_at' is the field name for registration time
      },
    });
  });
});



// =================== CRUD FORUM ===================
// POST: Create Forum Post
router.post("/forum", upload.single("image"), async (req, res) => {
  try {
    const { title, description, username } = req.body;
    const image = req.file ? req.file.path : null;
    const currentTime = new Date();

    // Cari user_id dan profilePhoto berdasarkan username
    const getUserIdQuery = `SELECT id, profilePhoto FROM users WHERE username = ?`;
    db.query(getUserIdQuery, [username], (err, userResult) => {
      if (err) {
        return res.status(500).json({ message: "Error fetching user_id", error: err });
      }

      if (userResult.length === 0) {
        return res.status(404).json({ message: "Username not found" });
      }

      const user_id = userResult[0].id;
      const userProfilePhoto = userResult[0].profilePhoto;

      // Insert forum post
      const insertForumQuery = `INSERT INTO forums (title, description, username, image, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?)`;
      db.query(insertForumQuery, [title, description, username, image, user_id, currentTime], (err, forumResult) => {
        if (err) {
          return res.status(500).json({ message: "Error creating forum post", error: err });
        }

        const forumId = forumResult.insertId;

        // Tidak ada notifikasi post, hanya mengirim respons keberhasilan
        res.status(201).json({
          message: "Post created successfully",
          postId: forumId
        });
      });
    });
  } catch (error) {
    console.error("Unexpected Error:", error);
    res.status(500).json({ message: "Unexpected error occurred", error: error.message || "Unknown error" });
  }
});


// Rute POST /comment untuk menambah komentar dan notifikasi
router.post('/comment', (req, res) => {
  const { comment, postId, userId } = req.body;  // Mendapatkan data dari body
  const currentTime = new Date().toISOString();  // Menggunakan format ISO untuk waktu

  console.log("Received postId:", postId);  // Menambahkan log untuk memeriksa nilai postId

  // 1. Dapatkan pemilik forum berdasarkan postId
  const getForumOwnerQuery = `SELECT user_id FROM forums WHERE id = ?`;
  db.query(getForumOwnerQuery, [postId], (err, forumResult) => {
    if (err) {
      console.error("Error fetching forum:", err);
      return res.status(500).json({ message: "Error fetching forum", error: err });
    }

    console.log("Forum Result:", forumResult); // Debugging log untuk melihat hasil query

    if (forumResult.length === 0) {
      return res.status(404).json({ message: "Forum not found" });
    }

    const recipientId = forumResult[0].user_id;  // ID pemilik forum

    if (!recipientId) {
      return res.status(404).json({ message: "Recipient (forum owner) not found" });
    }

    // 2. Ambil nama dan username pemilik forum
    const getRecipientQuery = `SELECT name, username FROM users WHERE id = ?`;
    db.query(getRecipientQuery, [recipientId], (err, recipientResult) => {
      if (err) {
        console.error("Error fetching recipient data:", err);
        return res.status(500).json({ message: "Error fetching recipient data", error: err });
      }

      if (recipientResult.length === 0) {
        return res.status(404).json({ message: "Recipient not found" });
      }

      const recipientName = recipientResult[0].name;
      const recipientUsername = recipientResult[0].username;  // Username pemilik forum

      // 3. Ambil nama dan foto profil pengguna yang memberi komentar
      const getUserQuery = `SELECT name, profilePhoto FROM users WHERE id = ?`;
      db.query(getUserQuery, [userId], (err, userResult) => {
        if (err) {
          console.error("Error fetching user data:", err);
          return res.status(500).json({ message: "Error fetching user data", error: err });
        }

        if (userResult.length === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        const userName = userResult[0].name;
        const userProfilePhoto = userResult[0].profilePhoto;

        // 4. Insert komentar ke dalam database
        const insertCommentQuery = `
        INSERT INTO comments (comment, post_id, user_id, created_at) 
        VALUES (?, ?, ?, ?)
      `;
      const currentTime = new Date().toISOString().slice(0, 19).replace('T', ' ');
      
      // Debugging log: menampilkan nilai yang dikirim ke query
      console.log("Inserting comment with values: ", [comment, postId, userId, currentTime]);
      
      db.query(insertCommentQuery, [comment, postId, userId, currentTime], (err, insertResult) => {
        if (err) {
          console.error("Error inserting comment:", err);
          return res.status(500).json({ message: "Error inserting comment", error: err });
        }
        // lanjutkan dengan logika lainnya
      });
      
      
          // 5. Buat notifikasi komentar
          const title = `${userName} telah memberi komentar pada postingan Anda.`;
          const message = `${userName} telah memberi komentar pada postingan Anda: "${comment}"`;

          // 6. Insert notifikasi ke database
          const notificationQuery = `
            INSERT INTO notifications 
            (title, message, user_id, profilePhoto, action_type, created_at, recipient_id, username, user_photo, recipient_name, recipient_username) 
            VALUES 
            (?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?)
          `;

          // Debugging log: Menampilkan nilai yang akan dimasukkan ke dalam database
          console.log("Inserting notification with values: ", [
            title,
            message,
            userId,  // ID pemberi komentar
            userProfilePhoto,
            'comment',
            recipientId,  // ID pemilik forum
            userName,  // Username pemberi komentar
            userProfilePhoto,
            recipientName,  // Nama pemilik forum
            recipientUsername  // Username pemilik forum
          ]);

          db.query(notificationQuery, [
            title,
            message,
            userId,  // ID pemberi komentar
            userProfilePhoto,
            'comment',
            recipientId,  // ID pemilik forum
            userName,  // Username pemberi komentar
            userProfilePhoto,
            recipientName,  // Nama pemilik forum
            recipientUsername  // Username pemilik forum
          ], (err, insertNotificationResult) => {
            if (err) {
              console.error("Error inserting notification:", err);
              return res.status(500).json({ message: "Error inserting notification", error: err });
            }

            // 7. Kirim response sukses setelah menambahkan komentar dan notifikasi
            console.log("Comment and notification inserted successfully");
            res.status(200).json({ message: "Comment added and notification created successfully" });
          });
        });
      });
    });
  });

// Rute POST /like untuk memberi like pada postingan
router.post('/like', (req, res) => {
  const { forumId, userId } = req.body; // forumId = ID forum yang di-like, userId = ID yang memberi like

  // 1. Dapatkan pemilik postingan (forum) berdasarkan forumId
  const getForumOwnerQuery = `SELECT user_id FROM forums WHERE id = ?`;
  db.query(getForumOwnerQuery, [forumId], (err, result) => {
    if (err) {
      console.error("Error fetching forum:", err);
      return res.status(500).json({ message: "Error fetching forum", error: err });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Forum not found" });
    }

    const recipientId = result[0].user_id; // ID pemilik forum (posting)

    // 2. Ambil nama dan username pemilik forum (posting)
    const getRecipientQuery = `SELECT name, username FROM users WHERE id = ?`;
    db.query(getRecipientQuery, [recipientId], (err, recipientResult) => {
      if (err) {
        console.error("Error fetching recipient data:", err);
        return res.status(500).json({ message: "Error fetching recipient data", error: err });
      }

      if (recipientResult.length === 0) {
        return res.status(404).json({ message: "Recipient not found" });
      }

      const recipientName = recipientResult[0].name;
      const recipientUsername = recipientResult[0].username; // Username pemilik postingan

      // 3. Ambil nama dan foto profil pengguna yang memberi like
      const getUserQuery = `SELECT name, profilePhoto FROM users WHERE id = ?`;
      db.query(getUserQuery, [userId], (err, userResult) => {
        if (err) {
          console.error("Error fetching user data:", err);
          return res.status(500).json({ message: "Error fetching user data", error: err });
        }

        if (userResult.length === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        const userName = userResult[0].name;
        const userProfilePhoto = userResult[0].profilePhoto;

        // 4. Buat notifikasi like
        const title = `${userName} telah memberi like pada postingan Anda.`;  // Nama pemberi like
        const message = `${userName} telah memberi like pada postingan Anda.`;  // Pesan notifikasi

        // 5. Insert notifikasi ke database
        const notificationQuery = `
          INSERT INTO notifications 
          (title, message, user_id, profilePhoto, action_type, created_at, recipient_id, username, user_photo, recipient_name, recipient_username) 
          VALUES 
          (?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?)
        `;

        // Debugging log: Menampilkan nilai yang akan dimasukkan ke dalam database
        console.log("Inserting notification with values: ", [
          title,
          message,
          userId,  // ID pemberi like
          userProfilePhoto,
          'like',
          recipientId,  // ID pemilik postingan
          userName,  // Username pemberi like
          userProfilePhoto,
          recipientName,  // Nama pemilik postingan
          recipientUsername  // Username pemilik postingan
        ]);

        db.query(notificationQuery, [
          title,
          message,
          userId,  // ID pemberi like
          userProfilePhoto,
          'like',
          recipientId,  // ID pemilik postingan
          userName,  // Username pemberi like
          userProfilePhoto,
          recipientName,  // Nama pemilik postingan
          recipientUsername  // Username pemilik postingan
        ], (err, insertResult) => {
          if (err) {
            console.error("Error inserting notification:", err);
            return res.status(500).json({ message: "Error inserting notification", error: err });
          }

          // 6. Kirim response sukses setelah menambahkan like dan notifikasi
          console.log("Notification inserted successfully");
          res.status(200).json({ message: "Like added and notification created successfully" });
        });
      });
    });
  });
});


// GET: Get Forum Image Links
router.get("/forums/images", (req, res) => {
  const query = `SELECT id, image FROM forums WHERE image IS NOT NULL`;
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching forum images", error: err });
    }

    const imageLinks = results.map((forum) => {
      let imageUrl = forum.image;
      
      // Check if the image is a local path and modify it accordingly (if needed)
      if (!imageUrl.startsWith("http")) {
        // Assuming the images are stored in the cloud, prepend the base URL for cloud storage
        imageUrl = `https://console.cloud.google.com/storage/browser/api-fitur/${imageUrl}`;
      }

      return {
        id: forum.id,
        imageUrl: imageUrl, // Provide the complete URL
      };
    });

    res.status(200).json({
      error: false,
      message: "Forum images fetched successfully",
      images: imageLinks,
    });
  });
});


// GET: Get All Forums
router.get("/forums", (req, res) => {
  const query = `SELECT id, title, description, username, image FROM forums`;
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({
        message: "Error fetching forums",
        error: err,
        timestamp: new Date().toISOString(),
      });
    }

    // Base URL untuk membangun link gambar
    const baseUrl = `${req.protocol}://${req.get("host")}`;
    const forums = results.map(forum => ({
      id: forum.id,
      title: forum.title,
      description: forum.description,
      username: forum.username,
      imageUrl: forum.image
        ? `${baseUrl}/${forum.image.replace(/\s+/g, "_")}` // Ganti spasi di respons
        : null,
    }));

    res.status(200).json({
      message: "Forums fetched successfully",
      timestamp: new Date().toISOString(),
      forums,
    });
  });
});



// GET: Get Forum by ID
router.get("/forum/:id", (req, res) => {
  const { id } = req.params;

  const query = `SELECT * FROM forums WHERE id = ?`;
  db.query(query, [id], (err, result) => {
    if (err) return res.status(500).json({ message: "Error fetching forum data", error: err });

    if (result.length === 0) {
      return res.status(404).json({ message: "Forum not found" });
    }

    // Base URL untuk gambar
    const baseUrl = `${req.protocol}://${req.get("host")}/uploads`;
    const forum = result[0];
    forum.imageUrl = forum.image
      ? `${baseUrl}/${forum.image.replace(/\s+/g, "_")}`  // Ganti spasi dengan "_"
      : null; // Fallback jika image null

    res.status(200).json(forum);
  });
});

// DELETE: Delete Forum Post
router.delete("/forum/:id", (req, res) => {
  const { id } = req.params;

  const deleteCommentsQuery = `DELETE FROM comments WHERE post_id = ?`;
  db.query(deleteCommentsQuery, [id], (err) => {
    if (err) {
      return res.status(500).json({ message: "Error deleting comments", error: err });
    }

    const deleteForumQuery = `DELETE FROM forums WHERE id = ?`;
    db.query(deleteForumQuery, [id], (err, result) => {
      if (err) {
        return res.status(500).json({ message: "Error deleting forum post", error: err });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Forum post not found" });
      }
      res.status(200).json({ message: "Forum post deleted successfully" });
    });
  });
});

// =================== CRUD NOTIFICATION ===================

// POST: Create Notification (Protected Route)
router.post("/notification", authenticateToken, (req, res) => {
  const { title, message, user_id, activity, profile_photo } = req.body;

  const query = `
    INSERT INTO notifications (title, message, user_id, activity, profile_photo, time)
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  `;
  db.query(query, [title, message, user_id, activity, profile_photo], (err, result) => {
    if (err) return res.status(500).json({ message: "Error creating notification", error: err });
    res.status(201).json({ message: "Notification created successfully" });
  });
});

// Rute GET /notifications
router.get('/notifications', (req, res) => {
  const query = `
    SELECT 
      notifications.id,
      notifications.title,
      notifications.message,
      notifications.user_id,
      notifications.profilePhoto,
      notifications.action_type,
      notifications.created_at,
      notifications.recipient_id,
      users.name AS user_name,  -- Nama pemberi like/komentar
      users.username AS user_username,  -- Username pemberi like/komentar
      users.profilePhoto AS user_photo,
      recipient.name AS recipient_name,  -- Nama penerima (pemilik forum)
      recipient.username AS recipient_username,  -- Username penerima
      recipient.profilePhoto AS recipient_photo
    FROM notifications
    JOIN users ON notifications.user_id = users.id
    LEFT JOIN users AS recipient ON notifications.recipient_id = recipient.id
    WHERE notifications.action_type IN ('like', 'comment')  -- Hanya ambil notifikasi 'like' dan 'comment'
    ORDER BY notifications.created_at DESC
  `;

  db.query(query, (err, result) => {
    if (err) {
      console.error("Error fetching notifications:", err);
      return res.status(500).json({ message: "Error fetching notifications", error: err });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "No notifications found" });
    }

    res.status(200).json(result);  // Mengirim hasil notifikasi
  });
});

// =================== CRUD LIKE ===================

// GET: Get All Likes by Post ID
router.get('/likes/:post_id', (req, res) => {
  const { post_id } = req.params;

  const query = `SELECT * FROM likes WHERE post_id = ?`;
  db.query(query, [post_id], (err, results) => {
    if (err) {
      console.error('Error fetching likes:', err);
      return res.status(500).json({ message: 'Error fetching likes', error: err });
    }

    const likeCount = results.length;
    res.status(200).json({
      post_id: post_id,
      like_count: likeCount,
      likes: results,
    });
  });
});

// GET: Get All Likes by User ID
router.get('/likes/user/:user_id', (req, res) => {
  const { user_id } = req.params;

  const query = `SELECT * FROM likes WHERE user_id = ?`;
  db.query(query, [user_id], (err, results) => {
    if (err) {
      console.error('Error fetching user likes:', err);
      return res.status(500).json({ message: 'Error fetching likes', error: err });
    }

    res.status(200).json({
      user_id: user_id,
      like_count: results.length,
      likes: results,
    });
  });
});

// DELETE: Remove Like
router.delete('/like/:id', (req, res) => {
  const { id } = req.params;

  const query = `DELETE FROM likes WHERE id = ?`;
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error deleting like:', err);
      return res.status(500).json({ message: 'Error deleting like', error: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Like not found' });
    }
    res.status(200).json({ message: 'Like removed successfully' });
  });
});

module.exports = router;
