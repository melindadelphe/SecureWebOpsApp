import express from 'express';
import multer from 'multer';
import { createClient } from '@supabase/supabase-js';
import { encryptPDF } from '../services/encryptionServices.js'; // Added .js extension

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

router.post('/encrypt', upload.single('pdf'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "No file uploaded" });

        const kmsKey = process.env.KMS_MASTER_SECRET;
        const encryptedFile = encryptPDF(req.file.buffer, kmsKey);

        const fileName = `secure_${Date.now()}.pdf.enc`;
        const { error: storageError } = await supabase.storage
            .from('secure-files')
            .upload(fileName, encryptedFile);

        if (storageError) throw storageError;

        // Audit Log entry matching Melinda's compliance role
        await supabase.from('audit_logs').insert({
            action: 'PDF_ENCRYPTED',
            details: `File: ${req.file.originalname} encrypted by backend`,
            timestamp: new Date().toISOString()
        });

        res.json({ success: true, file: fileName });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

export default router;