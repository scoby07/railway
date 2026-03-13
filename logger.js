// utils/logger.js — Structured production logging

const winston = require('winston');
require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');

const LOG_DIR = process.env.LOG_DIR || './logs';
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

// ── Format ────────────────────────────────────────────────────────────────────
const jsonFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    const extra = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
    return `${timestamp} [${level}]: ${message}${extra}`;
  })
);

// ── Transports ────────────────────────────────────────────────────────────────
const transports = [
  // General app log
  new winston.transports.DailyRotateFile({
    filename: path.join(LOG_DIR, 'app-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxFiles: '30d',
    maxSize: '50m',
    format: jsonFormat,
    level: 'info'
  }),
  // Error-only log
  new winston.transports.DailyRotateFile({
    filename: path.join(LOG_DIR, 'error-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxFiles: '90d',
    maxSize: '50m',
    format: jsonFormat,
    level: 'error'
  }),
  // Security events (login failures, blocked IPs, etc.)
  new winston.transports.DailyRotateFile({
    filename: path.join(LOG_DIR, 'security-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxFiles: '90d',
    maxSize: '50m',
    format: jsonFormat,
    level: 'warn'
  })
];

if (process.env.NODE_ENV !== 'production') {
  transports.push(new winston.transports.Console({ format: consoleFormat }));
}

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  transports,
  exitOnError: false
});

// ── Security-specific logger helper ─────────────────────────────────────────
logger.security = (event, details = {}) => {
  logger.warn(event, { security: true, ...details });
};

module.exports = logger;
