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
  db.query(query, (err, result) => {
    if (err) return res.status(500).json({ message: "Error fetching users", error: err });
    res.status(200).json(result);
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

    res.status(200).json(result[0]);
  });
});


// GET: Get User Profile Photo Links
router.get("/users/profile-photos", (req, res) => {
  const query = `SELECT id, username, profilePhoto FROM users WHERE profilePhoto IS NOT NULL`;
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching user profile photos", error: err });
    }

    const profilePhotoLinks = results.map((user) => {
      let profilePhotoUrl = user.profilePhoto;

      // Gantilah path ini dengan URL HTTPS yang sesuai jika gambar berada di server lain
      if (profilePhotoUrl) {
        profilePhotoUrl = `https://console.cloud.google.com/storage/browser/api-fitur/${profilePhotoUrl.replace(/\\/g, '/')}`;
      }

      return {
        id: user.id,
        username: user.username,
        profilePhotoUrl: profilePhotoUrl,
      };
    });

    res.status(200).json({ profilePhotos: profilePhotoLinks });
  });
});


// PUT: Edit User (Allowing phone and photo to be updated)
router.put(
  "/user/:id",
  upload.single("profilePhoto"), 
  [
    body("phone").optional().isMobilePhone().withMessage("Valid phone number is required"), 
  ],
  async (req, res) => {
    const { id } = req.params;
    const { phone } = req.body;
    const photo = req.file ? req.file.path : null;

    const updateFields = [];
    const updateValues = [];

    if (phone) {
      updateFields.push("phone = ?");
      updateValues.push(phone);
    }

    if (photo) {
      updateFields.push("profilePhoto = ?");
      updateValues.push(photo);  
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ message: "No fields to update" });
    }

    updateValues.push(id);

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

        // Insert notification for forum post creation with delay
        const notificationMessage = `${username} telah membuat posting baru: "${title}"`;
        const insertNotificationQuery = `INSERT INTO notifications (title, message, user_id, profilePhoto, action_type, created_at) VALUES (?, ?, ?, ?, 'post', ?)`;

        setTimeout(() => {
          db.query(insertNotificationQuery, [title, notificationMessage, user_id, userProfilePhoto, currentTime], (err, notifResult) => {
            if (err) {
              return res.status(500).json({ message: "Error creating notification", error: err });
            }

            res.status(201).json({
              message: "Post and notification created successfully",
              postId: forumId,
              notificationId: notifResult.insertId,
            });
          });
        }, 10000); // 10 detik delay untuk notifikasi
      });
    });
  } catch (error) {
    console.error("Unexpected Error:", error);
    res.status(500).json({ message: "Unexpected error occurred", error: error.message || "Unknown error" });
  }
});


// POST: Create Comment
router.post("/comment", async (req, res) => {
  try {
    const { comment, post_id, username } = req.body;
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

      // Insert comment
      const insertCommentQuery = `INSERT INTO comments (post_id, comment, user_id, created_at) VALUES (?, ?, ?, ?)`;
      db.query(insertCommentQuery, [post_id, comment, user_id, currentTime], (err, commentResult) => {
        if (err) {
          return res.status(500).json({ message: "Error creating comment", error: err });
        }

        // Insert notification for comment with delay
        const insertNotificationQuery = `INSERT INTO notifications (title, message, user_id, profilePhoto, action_type, created_at) VALUES (?, ?, ?, ?, 'comment', ?)`;
        const notificationMessage = `${username} telah memberi komentar pada postingan Anda: "${comment}"`;

        setTimeout(() => {
          db.query(insertNotificationQuery, [comment, notificationMessage, user_id, userProfilePhoto, currentTime], (err, notifResult) => {
            if (err) {
              return res.status(500).json({ message: "Error creating notification", error: err });
            }

            res.status(201).json({
              message: "Comment and notification created successfully",
              commentId: commentResult.insertId,
              notificationId: notifResult.insertId,
            });
          });
        }, 10000); // 10 detik delay untuk notifikasi
      });
    });
  } catch (error) {
    console.error("Unexpected Error:", error);
    res.status(500).json({ message: "Unexpected error occurred", error: error.message || "Unknown error" });
  }
});

// POST: Create Like
router.post("/like", async (req, res) => {
  try {
    const { post_id, username } = req.body;
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

      // Check if the user has already liked the post
      const checkLikeQuery = `SELECT * FROM likes WHERE post_id = ? AND user_id = ?`;
      db.query(checkLikeQuery, [post_id, user_id], (err, likeResult) => {
        if (err) {
          return res.status(500).json({ message: "Error checking like", error: err });
        }

        if (likeResult.length > 0) {
          return res.status(400).json({ message: "You have already liked this post" });
        }

        // Insert like
        const insertLikeQuery = `INSERT INTO likes (post_id, user_id, created_at) VALUES (?, ?, ?)`;
        db.query(insertLikeQuery, [post_id, user_id, currentTime], (err, likeResult) => {
          if (err) {
            return res.status(500).json({ message: "Error creating like", error: err });
          }

          // Insert notification for like with delay
          const insertNotificationQuery = `INSERT INTO notifications (title, message, user_id, profilePhoto, action_type, created_at) VALUES (?, ?, ?, ?, 'like', ?)`;
          const notificationMessage = `${username} telah memberi like pada postingan Anda.`;

          setTimeout(() => {
            db.query(insertNotificationQuery, [username, notificationMessage, user_id, userProfilePhoto, currentTime], (err, notifResult) => {
              if (err) {
                return res.status(500).json({ message: "Error creating notification", error: err });
              }

              res.status(201).json({
                message: "Like and notification created successfully",
                likeId: likeResult.insertId,
                notificationId: notifResult.insertId,
              });
            });
          }, 10000); // 10 detik delay untuk notifikasi
        });
      });
    });
  } catch (error) {
    console.error("Unexpected Error:", error);
    res.status(500).json({ message: "Unexpected error occurred", error: error.message || "Unknown error" });
  }
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

    res.status(200).json(result[0]);
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

// GET: Get Notifications (Protected Route)
router.get("/notifications", authenticateToken, (req, res) => {
  const query = `
    SELECT 
      notifications.*, 
      users.name AS username, 
      users.photo AS profile_photo
    FROM notifications
    JOIN users ON notifications.user_id = users.id
    ORDER BY time DESC
  `;
  db.query(query, (err, result) => {
    if (err) return res.status(500).json({ message: "Error fetching notifications", error: err });
    res.status(200).json(result);
  });
});


// =================== CRUD COMMENT ===================
// GET: Get Comments by Post ID
router.get('/forum/comment/:id', async (req, res) => {
    const forumId = req.params.id;
    console.log(`Fetching comments for forum ID: ${forumId}`);

    try {
        db.query(
            'SELECT * FROM comments WHERE post_id = ?',
            [forumId],
            (err, results) => {
                if (err) {
                    console.error('Error fetching comments:', err);
                    return res.status(500).json({ message: 'Error fetching comments', error: err });
                }
                if (results.length === 0) {
                    return res.status(404).json({ message: 'No comments found for this forum.' });
                }
                res.status(200).json(results);
            }
        );
    } catch (error) {
        console.error('Error fetching comments:', error);
        res.status(500).json({ message: 'Error fetching comments', error });
    }
});

// DELETE: Delete Comment by ID
router.delete('/comment/:id', (req, res) => {
  const { id } = req.params;

  const query = `DELETE FROM comments WHERE id = ?`;
  db.query(query, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error deleting comment', error: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Comment not found' });
    }
    res.status(200).json({ message: 'Comment deleted successfully' });
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
