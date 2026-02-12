/**
 * @fileoverview PDF Encryption Page
 * * This page allows users to upload sensitive PDF documents for 
 * AES-256-GCM encryption before storage.
 * * Flow:
 * 1. User selects a PDF file locally.
 * 2. File is sent to the Proxmox Backend (172.20.0.220).
 * 3. Backend encrypts the file and logs the action in Supabase.
 * 4. User receives a success confirmation and an encrypted download link.
 * * @module pages/PDFEncryption
 */

import React, { useState } from 'react';
import { Shield, FileUp, Lock, CheckCircle, AlertCircle, Loader2 } from 'lucide-react';

export default function PDFEncryption() {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');

  // POINTING TO YOUR PROXMOX SERVER
  const BACKEND_URL = "http://localhost:3000/api/pdf/upload";

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    setStatus('uploading');
    const formData = new FormData();
    formData.append('pdf', file);

    try {
      const response = await fetch(BACKEND_URL, {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        setStatus('success');
        setMessage('File encrypted and stored successfully on the secure server.');
      } else {
        throw new Error('Encryption failed. Check backend logs.');
      }
    } catch (error) {
      console.error(error);
      setStatus('error');
      setMessage('Could not connect to the Proxmox server. Ensure port 3000 is open.');
    }
  };

  return (
    <div className="space-y-6 pb-20 lg:pb-0">
      <div>
        <h1 className="text-2xl lg:text-3xl font-bold font-display">Secure PDF Vault</h1>
        <p className="text-muted-foreground mt-1">AES-256 encryption for sensitive business documents</p>
      </div>

      <div className="max-w-2xl mx-auto bg-card rounded-xl border shadow-card p-8">
        {status === 'idle' || status === 'uploading' ? (
          <div className="space-y-6 text-center">
            <div className="border-2 border-dashed border-muted rounded-lg p-10 flex flex-col items-center justify-center space-y-4">
              <FileUp className="w-12 h-12 text-primary" />
              <div>
                <p className="font-medium">{file ? file.name : "Select a PDF document"}</p>
                <p className="text-xs text-muted-foreground">Max file size: 10MB</p>
              </div>
              <input 
                type="file" 
                accept="application/pdf" 
                onChange={handleFileChange}
                className="hidden" 
                id="pdf-upload"
              />
              <label 
                htmlFor="pdf-upload" 
                className="bg-secondary text-secondary-foreground px-4 py-2 rounded-md cursor-pointer hover:bg-secondary/80 transition-colors"
              >
                Browse Files
              </label>
            </div>

            <button
              onClick={handleUpload}
              disabled={!file || status === 'uploading'}
              className="w-full flex items-center justify-center gap-2 bg-primary text-primary-foreground py-3 rounded-lg font-semibold disabled:opacity-50"
            >
              {status === 'uploading' ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Encrypting locally...
                </>
              ) : (
                <>
                  <Lock className="w-5 h-5" />
                  Encrypt & Secure
                </>
              )}
            </button>
          </div>
        ) : (
          <div className="text-center space-y-4 py-6">
            {status === 'success' ? (
              <CheckCircle className="w-16 h-16 text-green-500 mx-auto" />
            ) : (
              <AlertCircle className="w-16 h-16 text-red-500 mx-auto" />
            )}
            <h3 className="text-xl font-bold">{status === 'success' ? 'Success!' : 'Error'}</h3>
            <p className="text-muted-foreground">{message}</p>
            <button 
              onClick={() => {setStatus('idle'); setFile(null);}}
              className="text-primary font-medium hover:underline"
            >
              Secure another file
            </button>
          </div>
        )}
      </div>

      {/* Security Context Note for Senior Design */}
      <div className="bg-muted/50 rounded-lg p-4 flex gap-3 items-start border">
        <Shield className="w-5 h-5 text-primary shrink-0 mt-0.5" />
        <p className="text-xs leading-relaxed text-muted-foreground">
          <strong>Security Note:</strong> Files are processed using an AES-256-GCM authenticated encryption cipher. 
          The master key is protected within the Proxmox environment and never exposed to the client-side browser.
        </p>
      </div>
    </div>
  );
}