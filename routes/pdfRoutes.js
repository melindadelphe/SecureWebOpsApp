import express from 'express';
import multer from 'multer';
import { encryptPDF } from '../services/encryptionServices.js';

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.post('/upload', upload.single('pdf'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "No file uploaded" });
        }

        const fileBuffer = req.file.buffer;
        const secretKey = process.env.KMS_MASTER_SECRET;

        // 1. Run the actual Encryption Logic
        const encryptedData = encryptPDF(fileBuffer, secretKey);
        
        console.log("SUCCESS: File encrypted locally (Demo Mode)");
        console.log("Encrypted Buffer Length:", encryptedData.length);

        // 2. Return success without calling Supabase
        res.status(200).json({
            success: true,
            message: "AES-256-GCM Encryption Complete! (Local Storage Simulated)",
            fileName: req.file.originalname
        });

    } catch (error) {
        console.error("Encryption Error:", error);
        res.status(500).json({ error: "Encryption failed" });
    }
});

// THIS IS THE LINE YOU ARE MISSING:
export default router;