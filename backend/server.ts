// Load environment variables, import core dependencies (Express, CORS, File System),
//  and initialize the server and analysis engine.
import 'dotenv/config';
import express = require('express');
import cors = require('cors');
import fs = require('fs');
import path = require('path');
import type { Request, Response } from 'express';
import EmailAnalyzer from './analyzer';

const app = express();
const PORT = process.env.PORT || 3000;
const emailAnalyzer = new EmailAnalyzer();

// Middleware setup
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Path for storing trusted senders locally
const TRUSTED_FILE = path.join(__dirname, 'trusted-senders.json');

// Helper to load trusted senders
function loadTrustedSenders(): string[] {
    try {
        if (fs.existsSync(TRUSTED_FILE)) {
            const data = fs.readFileSync(TRUSTED_FILE, 'utf-8');
            const parsed = JSON.parse(data);
            if (Array.isArray(parsed)) {
                return parsed;
            }
        }
    } catch (error) {
        console.error('Error loading trusted senders:', error);
    }
    return [];
}

// Helper to save trusted senders
function saveTrustedSender(email: string) {
    const senders = loadTrustedSenders();
    const normalized = email.trim().toLowerCase();
    if (!senders.includes(normalized)) {
        senders.push(normalized);
        fs.writeFileSync(TRUSTED_FILE, JSON.stringify(senders, null, 2), 'utf-8');
    }
}

// Main endpoint for email analysis
app.post('/api/analyze', async (req: Request, res: Response): Promise<void> => {
    const { sender, subject, body, isKnownSender } = req.body;

    if (
        typeof sender !== 'string' ||
        typeof body !== 'string' ||
        (subject !== undefined && subject !== null && typeof subject !== 'string') ||
        (isKnownSender !== undefined && typeof isKnownSender !== 'boolean')
    ) {
        res.status(400).json({ error: 'Missing required email components (sender, body)' });
        return;
    }

    // Check against locally stored trusted senders from feedback
    const trustedSenders = loadTrustedSenders();
    const senderEmailMatch = sender.match(/<([^>]+)>/);
    const rawEmail = (senderEmailMatch?.[1] ?? sender).trim().toLowerCase();
    const isStoredTrusted = trustedSenders.includes(rawEmail);

    const finalIsKnownSender = (isKnownSender ?? false) || isStoredTrusted;

    const result = await emailAnalyzer.analyze(sender, subject ?? '', body, finalIsKnownSender);
    res.json(result);
});

app.post('/api/feedback', (req: Request, res: Response): void => {
    const { sender, subject, originalScore, userFeedback } = req.body ?? {};

    if (
        typeof sender !== 'string' ||
        typeof subject !== 'string' ||
        typeof originalScore !== 'number' ||
        !Number.isFinite(originalScore) ||
        originalScore < 0 ||
        originalScore > 100 ||
        (userFeedback !== 'Safe' && userFeedback !== 'Malicious')
    ) {
        res.status(400).json({ error: 'Invalid feedback payload.' });
        return;
    }

    // If user marked it as Safe, save the sender to the persistent JSON file
    if (userFeedback === 'Safe') {
        const senderEmailMatch = sender.match(/<([^>]+)>/);
        const rawEmail = senderEmailMatch?.[1] ?? sender;
        saveTrustedSender(rawEmail);
    }

    console.info('Received user feedback:\n' + JSON.stringify({
        sender,
        subject,
        originalScore,
        userFeedback,
        receivedAt: new Date().toISOString()
    }, null, 2));

    res.status(200).json({ success: true, message: 'Feedback received and saved if safe.' });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});