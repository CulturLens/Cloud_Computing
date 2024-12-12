// config/storage.js
const multer = require("multer");

// Konfigurasi penyimpanan file
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Folder tempat file disimpan
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const cleanName = file.originalname.replace(/\s+/g, "_"); // Ganti spasi dengan "_"
    cb(null, uniqueSuffix + cleanName);
  },
});

// Buat middleware multer
const upload = multer({ storage: storage });

module.exports = upload;
