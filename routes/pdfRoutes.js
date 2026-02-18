import express from 'express';
import multer from 'multer';
import { createClient } from '@supabase/supabase-js';
import { encryptPDF } from '../services/encryptionServices.js';
import { logEvent } from '../services/auditService.js'; // Melinda's Compliance Service

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// Initialize Supabase Connection
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

router.post('/upload', upload.single('pdf'), async (req, res) => {
    // Capture metadata for the Audit Log
    const ip = req.ip || req.headers['x-forwarded-for'] || '127.0.0.1';
    const fileName = req.file?.originalname || 'unknown_file';

    try {
        if (!req.file) {
            await logEvent({ action: 'UPLOAD_FAILURE', fileName: 'none', status: 'FAILED', ip, details: 'No file provided' });
            return res.status(400).json({ error: "No file uploaded" });
        }

        // 1. COMPLIANCE: Log the initial attempt
        await logEvent({ action: 'UPLOAD_ATTEMPT', fileName, status: 'PENDING', ip });

        const fileBuffer = req.file.buffer;
        const secretKey = process.env.KMS_MASTER_SECRET;

        // 2. Run the Encryption Logic (AES-256-GCM)
        const encryptedData = encryptPDF(fileBuffer, secretKey);
        
        // 3. Upload the encrypted blob to Supabase Storage
        const cloudFileName = `secure_${Date.now()}_${fileName}.enc`;
        const { data, error } = await supabase.storage
            .from('pdfs') 
            .upload(cloudFileName, encryptedData, {
                contentType: 'application/octet-stream',
                upsert: true
            });

        if (error) throw error;

        // 4. COMPLIANCE: Log the final success
        await logEvent({ 
            action: 'ENCRYPTION_SUCCESS', 
            fileName: cloudFileName, 
            status: 'SUCCESS', 
            ip,
            details: `Original size: ${fileBuffer.length} bytes`
        });

        res.status(200).json({
            success: true,
            message: "Securely Encrypted, Logged, and Stored in Cloud.",
            path: data.path
        });

    } catch (error) {
        // 5. COMPLIANCE: Log the failure for security monitoring
        console.error("Critical Security Error:", error);
        await logEvent({ 
            action: 'ENCRYPTION_FAILURE', 
            fileName, 
            status: 'FAILED', 
            ip, 
            details: error.message 
        });

        res.status(500).json({ error: "Security processing failed" });
    }
});

export default router;