// googleCloud.js
const { Storage } = require("@google-cloud/storage");

// Inisialisasi Google Cloud Storage
const storage = new Storage();
// ({
//   keyFilename:
//     "./serviceAccount.json", // Ganti dengan path ke file kredensial JSON Anda
  
// });

const bucket = storage.bucket("api-fitur"); // Ganti dengan nama bucket Anda

module.exports = { bucket };
